"""Organizational failure-mode ceremonies for SLIP-39 group-of-groups custody.

These tests are executable ceremony scripts for the recovery procedures described in
ORGANIZATIONAL-CEREMONIES.org.  Each test corresponds to one organizational failure
mode (lost card, revealed card, departed member, lost group, compromised group secret,
authority change) and asserts both the recoveries that MUST succeed and the refusals
that MUST occur.

Reference scheme used throughout (unless a test says otherwise):

    group_threshold 2 of 3 groups:
        G0 "Execs"  2 of 3
        G1 "Board"  3 of 5
        G2 "Vault"  2 of 2

All randomness is drawn from a seeded PRNG via the RANDOM_BYTES hook, so every test is
deterministic while still exercising the "fresh random polynomial" semantics that the
re-issue ceremonies depend on.
"""

import random
from typing import List, Optional, Tuple

import pytest

import shamir_mnemonic as shamir
from shamir_mnemonic import EncryptedMasterSecret, MnemonicError, Share
from shamir_mnemonic.shamir import (
    RawShare,
    _recover_secret,
    _recover_secret_rawshares,
    _split_secret,
    group_common_mnemonics,
    recover_group_rawshares,
)
from shamir_mnemonic.share import ShareCommonParameters, ShareGroupParameters

MS = b"ABCDEFGHIJKLMNOP"

GROUP_THRESHOLD = 2
GROUPS = [(2, 3), (3, 5), (2, 2)]  # G0 "Execs", G1 "Board", G2 "Vault"

SEED = 20260826


@pytest.fixture
def det_random(monkeypatch):
    """Route all library randomness through a seeded PRNG: deterministic tests, but
    each successive draw still differs (unlike the all-zeros patch used elsewhere),
    so a re-split really does land on a fresh polynomial."""
    rng = random.Random(SEED)
    monkeypatch.setattr(shamir.shamir, "RANDOM_BYTES", rng.randbytes)
    return rng


@pytest.fixture
def scheme(det_random) -> List[List[str]]:
    """The reference 2-of-(2/3, 3/5, 2/2) scheme, deterministically generated."""
    return shamir.generate_mnemonics(GROUP_THRESHOLD, GROUPS, MS)


# ---------------------------------------------------------------------------
# Ceremony primitives (test-local helpers over the PR #51 / library API).
#
# These are deliberately NOT added to the library: they document exactly which public
# primitives a ceremony needs, and where the current API falls short (see the org
# document's "API gaps" section).
# ---------------------------------------------------------------------------


def member_raw(mnemonic: str) -> RawShare:
    """A member card's point on the group's member polynomial."""
    share = Share.from_mnemonic(mnemonic)
    return RawShare(share.index, share.value)


def group_secret_of(
    member_mnemonics: List[str],
) -> Tuple[ShareCommonParameters, ShareGroupParameters, bytes]:
    """CEREMONY STEP: recover a single group's GROUP SECRET from its own member cards
    alone -- no other groups present, master secret never reconstructed.

    Uses the PR #51 public helpers group_common_mnemonics + recover_group_rawshares.
    The recovered RawShare.data is the group secret: the group's y-value on the
    scheme's group polynomial, digest-verified against the member polynomial.
    """
    common = group_common_mnemonics(member_mnemonics, strict=True)
    ((common_params, sharegroups),) = common.items()
    ((grouping, _),) = sharegroups.items()
    possibles = recover_group_rawshares(sharegroups)
    if grouping.group_index not in possibles:
        # NOTE (API behavior): recover_group_rawshares is non-strict -- an incomplete
        # or inconsistent group yields NOTHING rather than raising.  The ceremony
        # turns that silence into an explicit refusal.
        raise MnemonicError(
            f"Group {grouping.group_index} secret not recoverable from the "
            f"{len(member_mnemonics)} member cards provided"
        )
    ((rawshare, _used),) = possibles[grouping.group_index].items()
    return common_params, grouping, rawshare.data


def reissue_group(
    member_mnemonics: List[str],
    member_threshold: Optional[int] = None,
    member_count: Optional[int] = None,
) -> List[str]:
    """CEREMONY STEP: re-split one group's secret onto a FRESH random member
    polynomial, pinning all scheme metadata (identifier, extendable, iteration
    exponent, group index, group threshold, group count) so the new cards remain
    combinable with every untouched group.

    Member threshold and count may be changed (departed-member / extension variants).

    NOTE: the fresh split requires the private _split_secret; PR #51's public
    'expand' path only regenerates the ORIGINAL polynomial (see the org document,
    "API gaps").
    """
    common_params, grouping, secret = group_secret_of(member_mnemonics)
    if member_threshold is None:
        member_threshold = grouping.member_threshold
    if member_count is None:
        member_count = len(member_mnemonics) + 1
    raw_shares = _split_secret(member_threshold, member_count, secret)
    return [
        Share(
            common_params.identifier,
            common_params.extendable,
            common_params.iteration_exponent,
            grouping.group_index,
            common_params.group_threshold,
            common_params.group_count,
            index,
            member_threshold,
            value,
        ).mnemonic()
        for index, value in raw_shares
    ]


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


def test_baseline_scheme_recovers(scheme):
    """Sanity: the reference scheme recovers from any 2 complete groups, and refuses
    below threshold."""
    g0, g1, g2 = scheme
    assert shamir.combine_mnemonics(g0[:2] + g1[:3]) == MS
    assert shamir.combine_mnemonics(g1[2:] + g2) == MS
    assert shamir.combine_mnemonics(g0[1:] + g2) == MS
    # One complete group is not enough.
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(g1[:3])
    # A complete group plus an incomplete one is not enough.
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(g0[:2] + g1[:2])


# ---------------------------------------------------------------------------
# Key investigation: single-group recovery and re-issue
# ---------------------------------------------------------------------------


def test_recover_single_group_secret_isolated(scheme):
    """CEREMONY STEP (revealed-card ceremony, step RECOVER): the N-1 sound members of
    G1 recover their group's secret from their member cards ALONE.

    No other group participates; the master secret is never reconstructed.  The
    recovered value is digest-verified by the library (member polynomial digest).
    """
    g0, g1, g2 = scheme

    # 4 of 5 members present (member threshold 3): group secret recoverable.
    _, grouping, secret_a = group_secret_of(g1[:4])
    assert grouping.group_index == 1
    assert grouping.member_threshold == 3

    # A different member subset recovers the identical group secret.
    _, _, secret_b = group_secret_of(g1[2:])
    assert secret_a == secret_b

    # Cross-check the value is the true group-polynomial point: combining it with
    # G0's group secret (recovered the same way) reproduces the encrypted master
    # secret -- this is the ONLY step of this test that touches master-level data.
    common_params, _, secret_g0 = group_secret_of(g0)
    ciphertext = _recover_secret(
        common_params.group_threshold,
        [RawShare(0, secret_g0), RawShare(1, secret_a)],
    )
    ems = EncryptedMasterSecret(
        common_params.identifier,
        common_params.extendable,
        common_params.iteration_exponent,
        ciphertext,
    )
    assert ems.decrypt(b"") == MS

    # Below member threshold, the group secret is NOT recoverable.
    with pytest.raises(MnemonicError):
        group_secret_of(g1[:2])


def test_revealed_member_card_reissue_ceremony(scheme):
    """THE KEY CEREMONY: one G1 member's card is suspected revealed/copied.  The
    remaining 4 members re-issue the whole group on a fresh polynomial; G0 and G2 are
    never assembled and their cards are untouched.

    Ceremony script: RECOVER (group secret, members only) -> RE-SPLIT (fresh
    polynomial, pinned metadata) -> VERIFY (new cards work with untouched groups;
    old+new mixtures refuse) -> DESTROY (old cards; procedural, see org document).
    """
    g0, g1, g2 = scheme
    compromised = g1[4]  # the suspect card (member index 4)
    remaining = g1[:4]  # the 4 sound members; 4 >= member_threshold 3

    # RECOVER + RE-SPLIT: same 3-of-5 structure, fresh polynomial.
    new_g1 = reissue_group(remaining, member_threshold=3, member_count=5)
    assert len(new_g1) == 5

    # Metadata is pinned: every new card carries the same group parameters as the
    # old cards, so they are pool-compatible with untouched G0/G2.
    old_params = Share.from_mnemonic(g1[0]).group_parameters()
    for mnemonic in new_g1:
        assert Share.from_mnemonic(mnemonic).group_parameters() == old_params

    # The group secret is unchanged (it must be, to stay combinable) ...
    _, _, old_secret = group_secret_of(remaining)
    _, _, new_secret = group_secret_of(new_g1)
    assert new_secret == old_secret

    # ... but every card is new: no old card value or mnemonic reappears.
    assert not set(new_g1) & set(g1)
    old_values = {Share.from_mnemonic(m).value for m in g1}
    new_values = {Share.from_mnemonic(m).value for m in new_g1}
    assert not old_values & new_values

    # VERIFY 1: new G1 cards + untouched G0 cards recover the master secret.
    assert shamir.combine_mnemonics(new_g1[:3] + g0[:2]) == MS
    # VERIFY 2: new G1 cards + untouched G2 cards recover the master secret.
    assert shamir.combine_mnemonics(new_g1[2:] + g2) == MS
    # VERIFY 3: the untouched groups still work with each other.
    assert shamir.combine_mnemonics(g0[:2] + g2) == MS

    # VERIFY 4: the compromised card cannot combine with the NEW cards.  Old and new
    # cards lie on different member polynomials; the digest check refuses the mix.
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(g0[:2] + [compromised] + new_g1[:2])
    # ... at the group level, explicitly the digest refusal:
    with pytest.raises(MnemonicError, match="digest"):
        _recover_secret(
            3, [member_raw(compromised)] + [member_raw(m) for m in new_g1[:2]]
        )
    # ... and if the mixture collides on member index (old #4 vs new #4), the
    # duplicate index is refused even before the digest check.
    with pytest.raises(MnemonicError):
        _recover_secret(
            3, [member_raw(compromised)] + [member_raw(m) for m in new_g1[3:5]]
        )

    # VERIFY 5: after the old sound cards are destroyed, the compromised card's only
    # potential partners are the new cards (refused above) and other groups' cards --
    # with which it is a lone sub-threshold G1 member:
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(g0[:2] + [compromised])

    # WHY DESTRUCTION IS MANDATORY (procedural step): had the old cards NOT been
    # destroyed, they would still combine among themselves -- the math cannot revoke
    # them.  This is exactly the hazard the ceremony's DESTROY step controls.
    assert shamir.combine_mnemonics(g1[:3] + g0[:2]) == MS
    assert shamir.combine_mnemonics(([compromised] + remaining[:2]) + g2) == MS


def test_revealed_card_pr51_expand_is_not_revocation(scheme):
    """PR #51's 'expand' path regenerates the ORIGINAL member polynomial: expanding
    G1 back to 5 cards reproduces the compromised card VERBATIM.  Expand is the
    lost-card (regenerate-identical) tool, not the revealed-card (re-randomize) tool.
    """
    g0, g1, g2 = scheme
    compromised = g1[4]
    remaining = g1[:4]

    # Expand requires a master-quorum pool (G1 members alone are not sufficient for
    # group_ems_mnemonics): supply G0 as well.
    ((ems, recovered),) = shamir.group_ems_mnemonics(
        remaining + g0, expand=[(1, 5)], strict=True
    )
    assert ems.decrypt(b"") == MS
    # The 'new' group 1 is the OLD group 1 -- including the compromised card.
    assert recovered[1] == set(g1)
    assert compromised in recovered[1]


# ---------------------------------------------------------------------------
# Broader failure modes
# ---------------------------------------------------------------------------


def test_lost_member_card_regeneration(scheme):
    """Lost (not revealed) member card, group still at/above threshold: the group
    keeps working, and the identical card can be regenerated.

    Two paths:
      (a) PR #51 expand -- public API, but needs a master-quorum pool of mnemonics;
      (b) group-local -- only G1's members assemble, but needs the private
          _recover_secret_rawshares (documented API gap).
    """
    g0, g1, g2 = scheme
    lost = g1[2]
    remaining = g1[:2] + g1[3:]  # 4 sound members

    # The group (and scheme) still recovers without the lost card.
    assert shamir.combine_mnemonics(remaining[:3] + g0[:2]) == MS

    # (a) PR #51 expand path: regenerates the missing card identically.
    ((ems, recovered),) = shamir.group_ems_mnemonics(
        remaining + g0, expand=[(1, 5)], strict=True
    )
    assert ems.decrypt(b"") == MS
    assert lost in recovered[1]
    assert recovered[1] == set(g1)

    # (b) Group-local path: the 4 members alone recover ALL 5 original member
    # RawShares and re-mint the lost card verbatim -- no other group assembles.
    proto = Share.from_mnemonic(remaining[0])
    all_raw = _recover_secret_rawshares(
        proto.member_threshold, 5, [member_raw(m) for m in remaining]
    )
    (lost_value,) = [value for index, value in all_raw if index == 2]
    reminted = Share(
        proto.identifier,
        proto.extendable,
        proto.iteration_exponent,
        proto.group_index,
        proto.group_threshold,
        proto.group_count,
        2,
        proto.member_threshold,
        lost_value,
    ).mnemonic()
    assert reminted == lost


def test_departed_member_reissue_with_extension(scheme):
    """Departed member: same re-issue ceremony as a revealed card, here with member
    count extension 5 -> 6 AND member threshold change 3 -> 4."""
    g0, g1, g2 = scheme
    departed = g1[1]
    remaining = g1[:1] + g1[2:]  # 4 members remain, >= old threshold 3

    new_g1 = reissue_group(remaining, member_threshold=4, member_count=6)
    assert len(new_g1) == 6

    # Only member_threshold changed in the group parameters; all scheme-level
    # metadata is pinned.
    old_params = Share.from_mnemonic(g1[0]).group_parameters()
    new_params = Share.from_mnemonic(new_g1[0]).group_parameters()
    assert new_params == old_params._replace(member_threshold=4)

    # New quorum (4 of 6) + untouched groups recover; below new threshold refuses.
    assert shamir.combine_mnemonics(new_g1[:4] + g0[:2]) == MS
    assert shamir.combine_mnemonics(new_g1[2:] + g2) == MS
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(new_g1[:3] + g0[:2])

    # The departed member's card cannot combine with the new cards.
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(g0[:2] + [departed] + new_g1[:3])

    # Old cards among themselves would still work (destroy them): 3 old >= old
    # threshold 3.
    assert shamir.combine_mnemonics(remaining[:3] + g2) == MS


def test_lost_group_replacement(scheme):
    """Entire G1 lost (e.g. site disaster); remaining groups meet group_threshold.

    (a) PR #51 headline path: expand=[(1, 1)] replaces the lost 3-of-5 group with a
        new 1-of-1 card, from the other groups' cards alone.
    (b) Full-structure replacement (3-of-5 again, fresh member polynomial) via the
        private group-level primitives.

    Re-issue after LOSS restores availability only: the group secret at x=1 is fixed
    by interpolation, so IF the lost cards are ever found, they still work (asserted
    below).  Suspected theft therefore escalates to the master re-share ceremony.
    """
    g0, g1, g2 = scheme  # g1 is "lost"; keep it only to assert non-revocation

    # (a) PR #51 replacement with a single-card group (non-strict, since a 3-of-5
    # group is being replaced by 1-of-1).
    ((ems, recovered),) = shamir.group_ems_mnemonics(g0 + g2, expand=[(1, 1)])
    assert ems.decrypt(b"") == MS
    (replacement,) = recovered[1]
    assert Share.from_mnemonic(replacement).member_threshold == 1
    assert shamir.combine_mnemonics([replacement] + g2) == MS
    assert shamir.combine_mnemonics([replacement] + g0[1:]) == MS
    # 'strict' semantics: replacing an ABSENT group with a 1-of-1 is allowed even
    # under strict (nothing provided is being contradicted) ...
    ((_, recovered_strict),) = shamir.group_ems_mnemonics(
        g0 + g2, expand=[(1, 1)], strict=True
    )
    assert len(recovered_strict[1]) == 1
    # ... but strict DOES refuse when old cards of the group are present and would
    # be obsoleted by the 1-of-1 replacement:
    with pytest.raises(MnemonicError):
        list(shamir.group_ems_mnemonics(g0 + g2 + g1[:3], expand=[(1, 1)], strict=True))
    # PR #51 cannot re-issue a MULTI-card replacement for a lost group (API gap --
    # multi-card expansion needs the group's own members); strict says so:
    with pytest.raises(MnemonicError):
        list(shamir.group_ems_mnemonics(g0 + g2, expand=[(1, 5)], strict=True))

    # (b) Full-structure replacement: recover G0 and G2 group secrets from their own
    # members, interpolate the group polynomial to regenerate G1's group secret,
    # and split it onto a fresh 3-of-5 member polynomial.
    common_params, _, secret_g0 = group_secret_of(g0)
    _, _, secret_g2 = group_secret_of(g2)
    group_raw = _recover_secret_rawshares(
        common_params.group_threshold,
        common_params.group_count,
        [RawShare(0, secret_g0), RawShare(2, secret_g2)],
    )
    (secret_g1,) = [value for index, value in group_raw if index == 1]
    # The regenerated group secret necessarily equals the original:
    assert secret_g1 == group_secret_of(g1)[2]

    new_g1 = [
        Share(
            common_params.identifier,
            common_params.extendable,
            common_params.iteration_exponent,
            1,
            common_params.group_threshold,
            common_params.group_count,
            index,
            3,
            value,
        ).mnemonic()
        for index, value in _split_secret(3, 5, secret_g1)
    ]
    assert shamir.combine_mnemonics(new_g1[:3] + g0[:2]) == MS
    assert shamir.combine_mnemonics(new_g1[2:] + g2) == MS

    # The new cards are all fresh; lost cards cannot mix with them.
    assert not set(new_g1) & set(g1)
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(g0[:2] + [g1[0]] + new_g1[1:3])

    # NON-REVOCATION (the hazard): if the lost cards resurface, they still work.
    # Availability was restored; confidentiality was NOT rotated.
    assert shamir.combine_mnemonics(g1[:3] + g0[:2]) == MS


def test_add_group_authority_change(det_random):
    """Authority change: add a 4th group to an extendable scheme.

    group_count is baked into every card's metadata, so a true in-place addition is
    impossible; the supported ceremony re-encodes the SAME encrypted master secret
    into a parallel 4-group scheme (no passphrase needed, master secret never
    decrypted).  Old cards remain valid among themselves until deliberately
    destroyed; the two encodings refuse to mix.
    """
    old = shamir.generate_mnemonics(GROUP_THRESHOLD, GROUPS, MS, extendable=True)
    g0, g1, g2 = old

    # CEREMONY: assemble a quorum, recover the EMS (ciphertext only -- the
    # passphrase is never requested and the master secret never appears).
    ems = shamir.recover_ems(shamir.decode_mnemonics(g0[:2] + g1[:3]))

    # Re-encode with a 4th group, same group_threshold.
    new = shamir.split_ems(GROUP_THRESHOLD, GROUPS + [(2, 3)], ems)
    new_mnemonics = [[share.mnemonic() for share in group] for group in new]
    n0, n1, n2, n3 = new_mnemonics

    # The new encoding recovers the same master secret; the new group has authority.
    assert shamir.combine_mnemonics(n3[:2] + n0[:2]) == MS
    assert shamir.combine_mnemonics(n3[1:] + n2) == MS

    # Old cards are NOT invalidated: the old encoding still stands.
    assert shamir.combine_mnemonics(g0[:2] + g2) == MS

    # The encodings cannot mix: group_count differs (3 vs 4), so the common
    # parameters refuse before any math is attempted.
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(g0[:2] + n3[:2])

    # PR #51's expand path refuses to mint shares for a group index beyond the
    # declared group_count of the OLD encoding:
    with pytest.raises(MnemonicError):
        list(shamir.group_ems_mnemonics(g0 + g2, expand=[(3, 1)], strict=True))

    # OUT-OF-SPEC DEMONSTRATION (do not rely on it; see org document): the group
    # polynomial mathematically extends beyond group_count.  A "phantom" group-3
    # share crafted at the raw level, still claiming group_count=3, combines with
    # the ORIGINAL cards in this implementation.  Other SLIP-39 implementations may
    # reject group_index >= group_count; PR #51's guard above deliberately refuses
    # to create such shares.
    common_params, _, secret_g0 = group_secret_of(g0)
    _, _, secret_g2 = group_secret_of(g2)
    phantom_raw = _recover_secret_rawshares(
        common_params.group_threshold,
        4,  # one past the declared group_count of 3
        [RawShare(0, secret_g0), RawShare(2, secret_g2)],
    )
    (phantom_value,) = [value for index, value in phantom_raw if index == 3]
    phantom = Share(
        common_params.identifier,
        common_params.extendable,
        common_params.iteration_exponent,
        3,
        common_params.group_threshold,
        common_params.group_count,  # metadata still says 3 groups
        0,
        1,
        phantom_value,
    ).mnemonic()
    assert shamir.combine_mnemonics([phantom] + g0[:2]) == MS


def test_compromised_group_master_reshare(det_random):
    """EMERGENCY: G1's group secret must be assumed exposed (>= member_threshold
    cards copied).  No group-local ceremony can rotate it -- the group secret is a
    fixed point of the scheme's group polynomial.  The remedy is a full master-level
    re-share: recover the EMS at a quorum, re-encode EVERY group on a fresh group
    polynomial under a NEW identifier, and destroy all old cards.

    The master secret is never decrypted; the passphrase is never requested; no
    on-chain key movement is required (fewer than group_threshold group secrets were
    exposed, so the master secret itself is still safe).
    """
    old = shamir.generate_mnemonics(
        GROUP_THRESHOLD, GROUPS, MS, b"TREZOR", extendable=True
    )
    g0, g1, g2 = old

    # CEREMONY: quorum recovers the EMS -- ciphertext only.
    ems = shamir.recover_ems(shamir.decode_mnemonics(g0[:2] + g2))

    # Re-encode under a fresh identifier.  extendable=True makes the ciphertext
    # identifier-independent, so this needs no passphrase; with extendable=False the
    # identifier is bound into the KDF and rotating it would force decrypting the
    # master secret (see org document).
    new_id = (ems.identifier + 1) % (1 << 15)
    ems_new = EncryptedMasterSecret(
        new_id, ems.extendable, ems.iteration_exponent, ems.ciphertext
    )
    new = shamir.split_ems(GROUP_THRESHOLD, GROUPS, ems_new)
    new_mnemonics = [[share.mnemonic() for share in group] for group in new]
    n0, n1, n2 = new_mnemonics

    # VERIFY (passphrase-free): the new encoding carries the identical ciphertext.
    assert shamir.recover_ems(shamir.decode_mnemonics(n0[:2] + n1[:3])).ciphertext == (
        ems.ciphertext
    )
    # Ground truth: it decrypts to the same master secret.
    assert shamir.combine_mnemonics(n1[2:] + n2, b"TREZOR") == MS

    # The exposed G1 group secret is now worthless: the new scheme's G1 secret lies
    # on a FRESH group polynomial.
    old_secret_g1 = group_secret_of(g1)[2]
    new_secret_g1 = group_secret_of(n1)[2]
    assert old_secret_g1 != new_secret_g1

    # Old and new cards refuse to mix (identifier differs).
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(g1[:3] + n0[:2], b"TREZOR")

    # The math cannot revoke the old encoding itself: old cards among themselves
    # still recover.  DESTROY is a procedural step, and until it completes the old
    # cards remain a live quorum path.
    assert shamir.combine_mnemonics(g1[:3] + g2, b"TREZOR") == MS


# ---------------------------------------------------------------------------
# Unit-level guarantees the ceremonies rest on
# ---------------------------------------------------------------------------


def test_digest_rejects_mixed_polynomials(det_random):
    """The 4-byte member-polynomial digest is what makes a re-issued group's old
    cards worthless in mixed sets: shares of the SAME secret from DIFFERENT splits
    never interpolate to a digest-consistent polynomial."""
    secret = MS
    split_a = _split_secret(3, 5, secret)
    split_b = _split_secret(3, 5, secret)

    # Each split alone recovers the secret.
    assert _recover_secret(3, split_a[:3]) == secret
    assert _recover_secret(3, split_b[2:]) == secret

    # Any cross-polynomial mixture is refused by the digest check.
    with pytest.raises(MnemonicError, match="digest"):
        _recover_secret(3, [split_a[0], split_b[1], split_b[2]])
    with pytest.raises(MnemonicError, match="digest"):
        _recover_secret(3, [split_a[0], split_a[1], split_b[2]])

    # Colliding member indices are refused outright.
    with pytest.raises(MnemonicError, match="unique"):
        _recover_secret(3, [split_a[0], split_b[0], split_b[1]])
