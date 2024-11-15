import json
import secrets
import pytest
from itertools import combinations
from random import shuffle

import pytest
from bip32utils import BIP32Key

import shamir_mnemonic as shamir
from shamir_mnemonic import MnemonicError, Share

MS = b"ABCDEFGHIJKLMNOP"


def test_basic_sharing_random():
    secret = secrets.token_bytes(16)
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], secret)[0]
    assert shamir.combine_mnemonics(mnemonics[:3]) == shamir.combine_mnemonics(
        mnemonics[2:]
    )


def test_basic_sharing_fixed():
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS)[0]
    assert MS == shamir.combine_mnemonics(mnemonics[:3])
    assert MS == shamir.combine_mnemonics(mnemonics[1:4])
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(mnemonics[1:3])


def test_passphrase():
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR")[0]
    assert MS == shamir.combine_mnemonics(mnemonics[1:4], b"TREZOR")
    assert MS != shamir.combine_mnemonics(mnemonics[1:4])


def test_non_extendable():
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS, extendable=False)[0]
    assert MS == shamir.combine_mnemonics(mnemonics[1:4])


def test_iteration_exponent():
    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"TREZOR", iteration_exponent=1
    )[0]
    assert MS == shamir.combine_mnemonics(mnemonics[1:4], b"TREZOR")
    assert MS != shamir.combine_mnemonics(mnemonics[1:4])

    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"TREZOR", iteration_exponent=2
    )[0]
    assert MS == shamir.combine_mnemonics(mnemonics[1:4], b"TREZOR")
    assert MS != shamir.combine_mnemonics(mnemonics[1:4])


def test_group_sharing():
    group_threshold = 2
    group_sizes = (5, 3, 5, 1)
    member_thresholds = (3, 2, 2, 1)
    mnemonics = shamir.generate_mnemonics(
        group_threshold, list(zip(member_thresholds, group_sizes)), MS
    )

    # Test all valid combinations of mnemonics.
    for groups in combinations(zip(mnemonics, member_thresholds), group_threshold):
        for group1_subset in combinations(groups[0][0], groups[0][1]):
            for group2_subset in combinations(groups[1][0], groups[1][1]):
                mnemonic_subset = list(group1_subset + group2_subset)
                shuffle(mnemonic_subset)
                assert MS == shamir.combine_mnemonics(mnemonic_subset)

    # Minimal sets of mnemonics.
    assert MS == shamir.combine_mnemonics(
        [mnemonics[2][0], mnemonics[2][2], mnemonics[3][0]]
    )
    assert MS == shamir.combine_mnemonics(
        [mnemonics[2][3], mnemonics[3][0], mnemonics[2][4]]
    )

    # One complete group and one incomplete group out of two groups required.
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(mnemonics[0][2:] + [mnemonics[1][0]])

    # One group of two required.
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(mnemonics[0][1:4])


def test_group_sharing_threshold_1():
    group_threshold = 1
    group_sizes = (5, 3, 5, 1)
    member_thresholds = (3, 2, 2, 1)
    mnemonics = shamir.generate_mnemonics(
        group_threshold, list(zip(member_thresholds, group_sizes)), MS
    )

    # Test all valid combinations of mnemonics.
    for group, member_threshold in zip(mnemonics, member_thresholds):
        for group_subset in combinations(group, member_threshold):
            mnemonic_subset = list(group_subset)
            shuffle(mnemonic_subset)
            assert MS == shamir.combine_mnemonics(mnemonic_subset)


def test_all_groups_exist():
    for group_threshold in (1, 2, 5):
        mnemonics = shamir.generate_mnemonics(
            group_threshold, [(3, 5), (1, 1), (2, 3), (2, 5), (3, 5)], MS
        )
        assert len(mnemonics) == 5
        assert len(sum(mnemonics, [])) == 19


def test_invalid_sharing():
    # Short master secret.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(1, [(2, 3)], MS[:14])

    # Odd length master secret.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(1, [(2, 3)], MS + b"X")

    # Group threshold exceeds number of groups.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(3, [(3, 5), (2, 5)], MS)

    # Invalid group threshold.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(0, [(3, 5), (2, 5)], MS)

    # Member threshold exceeds number of members.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(2, [(3, 2), (2, 5)], MS)

    # Invalid member threshold.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(2, [(0, 2), (2, 5)], MS)

    # Group with multiple members and member threshold 1.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(2, [(3, 5), (1, 3), (2, 5)], MS)


def test_vectors():
    with open("vectors.json", "r") as f:
        vectors = json.load(f)
    for description, mnemonics, secret_hex, xprv in vectors:
        if secret_hex:
            secret = bytes.fromhex(secret_hex)
            assert secret == shamir.combine_mnemonics(
                mnemonics, b"TREZOR"
            ), 'Incorrect secret for test vector "{}".'.format(description)
            assert (
                BIP32Key.fromEntropy(secret).ExtendedKey() == xprv
            ), 'Incorrect xprv for test vector "{}".'.format(description)
        else:
            with pytest.raises(MnemonicError):
                shamir.combine_mnemonics(mnemonics)
                pytest.fail(
                    'Failed to raise exception for test vector "{}".'.format(
                        description
                    )
                )


def test_split_ems():
    encrypted_master_secret = shamir.EncryptedMasterSecret.from_master_secret(
        MS, b"TREZOR", identifier=42, extendable=True, iteration_exponent=1
    )
    grouped_shares = shamir.split_ems(1, [(3, 5)], encrypted_master_secret)
    mnemonics = [share.mnemonic() for share in grouped_shares[0]]

    recovered = shamir.combine_mnemonics(mnemonics[:3], b"TREZOR")
    assert recovered == MS


def test_recover_ems():
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR")[0]

    groups = shamir.decode_mnemonics(mnemonics[:3])
    encrypted_master_secret = shamir.recover_ems(groups)
    recovered = encrypted_master_secret.decrypt(b"TREZOR")
    assert recovered == MS


def test_group_ems_mnemonics(monkeypatch):
    monkeypatch.setattr(shamir.shamir, "RANDOM_BYTES", lambda n: n * b"\0")

    mnemonics_nonext_a = shamir.split_ems(
        2,
        [(1, 1), (2, 3), (3, 5)],
        shamir.EncryptedMasterSecret.from_master_secret(
            MS, b"TREZOR", identifier=0, extendable=False, iteration_exponent=1
        ),
    )
    # print( json.dumps( mnemonics_nonext_a, indent=4, default=str ))
    assert mnemonics_nonext_a == [
        [
            Share.from_mnemonic(
                "academic acid acrobat leader civil gross counter dictate fancy findings lair freshman kind justice apart quiet lunch short vitamins painting"
            )
        ],
        [
            Share.from_mnemonic(
                "academic acid beard leaf desktop crowd erode vegan season warmth warn craft ceramic picture wrote depend radar result dream that"
            ),
            Share.from_mnemonic(
                "academic acid beard lily dwarf aide unknown fancy merit grant sharp leaves blimp exotic sharp fancy salon forecast worthy taught"
            ),
            Share.from_mnemonic(
                "academic acid beard lungs center injury academic pupal hand surface volume have smart hormone wealthy echo capture year browser material"
            ),
        ],
        [
            Share.from_mnemonic(
                "academic acid ceramic learn academic academic academic academic academic academic academic academic academic academic academic academic academic ugly saver sack"
            ),
            Share.from_mnemonic(
                "academic acid ceramic lips dress custody tension wildlife forbid surprise ticket already ugly emerald laundry pickup deny exhaust cards orange"
            ),
            Share.from_mnemonic(
                "academic acid ceramic luxury acquire gross likely very swimming rhythm member carbon regret daisy vintage gravity pile arena quiet material"
            ),
            Share.from_mnemonic(
                "academic acid ceramic march dream estimate genuine ambition listen gesture harvest broken fiction hawk making safari mountain problem hospital snake"
            ),
            Share.from_mnemonic(
                "academic acid ceramic method diet drift sweater alto epidemic beyond analysis hearing timber vegan alto tidy obtain ceramic cricket sack"
            ),
        ],
    ]
    mnemonics_nonext_b = shamir.split_ems(
        2,
        [(1, 1), (2, 5), (3, 7)],  # <-- increase group member count
        shamir.EncryptedMasterSecret.from_master_secret(
            MS, b"TREZOR", identifier=0, extendable=False, iteration_exponent=1
        ),
    )
    # print( json.dumps( mnemonics_nonext_b, indent=4, default=str ))
    assert mnemonics_nonext_b == [
        [
            Share.from_mnemonic(
                "academic acid acrobat leader civil gross counter dictate fancy findings lair freshman kind justice apart quiet lunch short vitamins painting"
            )
        ],
        [
            Share.from_mnemonic(
                "academic acid beard leaf desktop crowd erode vegan season warmth warn craft ceramic picture wrote depend radar result dream that"
            ),
            Share.from_mnemonic(
                "academic acid beard lily dwarf aide unknown fancy merit grant sharp leaves blimp exotic sharp fancy salon forecast worthy taught"
            ),
            Share.from_mnemonic(
                "academic acid beard lungs center injury academic pupal hand surface volume have smart hormone wealthy echo capture year browser material"
            ),
            Share.from_mnemonic(
                "academic acid beard marathon criminal force perfect being dwarf energy scroll satoshi welfare lunar slush charity guilt briefing steady medal"
            ),
            Share.from_mnemonic(
                "academic acid beard merit calcium music reaction says swimming rhythm member carbon regret daisy vintage gravity pile crisis estimate crush"
            ),
        ],
        [
            Share.from_mnemonic(
                "academic acid ceramic learn academic academic academic academic academic academic academic academic academic academic academic academic academic ugly saver sack"
            ),
            Share.from_mnemonic(
                "academic acid ceramic lips dress custody tension wildlife forbid surprise ticket already ugly emerald laundry pickup deny exhaust cards orange"
            ),
            Share.from_mnemonic(
                "academic acid ceramic luxury acquire gross likely very swimming rhythm member carbon regret daisy vintage gravity pile arena quiet material"
            ),
            Share.from_mnemonic(
                "academic acid ceramic march dream estimate genuine ambition listen gesture harvest broken fiction hawk making safari mountain problem hospital snake"
            ),
            Share.from_mnemonic(
                "academic acid ceramic method diet drift sweater alto epidemic beyond analysis hearing timber vegan alto tidy obtain ceramic cricket sack"
            ),
            Share.from_mnemonic(
                "academic acid ceramic mortgage ancient beard duration wolf beam smirk ultimate helpful amuse rapids item election plastic library voting orange"
            ),
            Share.from_mnemonic(
                "academic acid ceramic nervous devote force galaxy veteran much priority losing injury frost swimming vegan learn dress ruler formal material"
            ),
        ],
    ]
    assert mnemonics_nonext_b[0] == mnemonics_nonext_a[0]
    assert mnemonics_nonext_b[1][:3] == mnemonics_nonext_a[1]
    assert mnemonics_nonext_b[2][:5] == mnemonics_nonext_a[2]

    mnemonics_extend_a = shamir.split_ems(
        2,
        [(1, 1), (2, 3), (3, 5)],
        shamir.EncryptedMasterSecret.from_master_secret(
            MS, b"TREZOR", identifier=0, extendable=True, iteration_exponent=1
        ),
    )
    # print( json.dumps( mnemonics_extend_a, indent=4, default=str ))
    assert mnemonics_extend_a == [
        [
            Share.from_mnemonic(
                "academic agency acrobat leader check clinic isolate slavery branch bulge hairy library emphasis slim fused both cargo predator network adult"
            )
        ],
        [
            Share.from_mnemonic(
                "academic agency beard leaf both husky alarm firefly obtain device response graduate bedroom flash luxury friendly grasp slice robin music"
            ),
            Share.from_mnemonic(
                "academic agency beard lily armed tadpole scroll dynamic security unwrap exercise require busy busy firefly drink item column costume nylon"
            ),
            Share.from_mnemonic(
                "academic agency beard lungs cinema device true move texture obesity freshman jury should sack froth custody froth race finance dwarf"
            ),
        ],
        [
            Share.from_mnemonic(
                "academic agency ceramic learn academic academic academic academic academic academic academic academic academic academic academic academic academic zero laundry presence"
            ),
            Share.from_mnemonic(
                "academic agency ceramic lips blind wireless process scramble military lecture diploma nylon birthday talent deal wealthy briefing edge geology scandal"
            ),
            Share.from_mnemonic(
                "academic agency ceramic luxury drove vampire criminal idea damage husband knife evening gross garlic check result extend work keyboard priority"
            ),
            Share.from_mnemonic(
                "academic agency ceramic march counter ancestor lizard railroad river usual estate software improve river behavior emperor envy elevator genre scholar"
            ),
            Share.from_mnemonic(
                "academic agency ceramic method change magazine exhaust forecast priority fused pink presence demand webcam violence visual crowd tendency declare coastal"
            ),
        ],
    ]
    mnemonics_extend_b = shamir.split_ems(
        2,
        [(1, 1), (2, 5), (3, 7)],  # <-- increase group member count
        shamir.EncryptedMasterSecret.from_master_secret(
            MS, b"TREZOR", identifier=0, extendable=True, iteration_exponent=1
        ),
    )
    # print( json.dumps( mnemonics_extend_b, indent=4, default=str ))
    assert mnemonics_extend_b == [
        [
            Share.from_mnemonic(
                "academic agency acrobat leader check clinic isolate slavery branch bulge hairy library emphasis slim fused both cargo predator network adult"
            )
        ],
        [
            Share.from_mnemonic(
                "academic agency beard leaf both husky alarm firefly obtain device response graduate bedroom flash luxury friendly grasp slice robin music"
            ),
            Share.from_mnemonic(
                "academic agency beard lily armed tadpole scroll dynamic security unwrap exercise require busy busy firefly drink item column costume nylon"
            ),
            Share.from_mnemonic(
                "academic agency beard lungs cinema device true move texture obesity freshman jury should sack froth custody froth race finance dwarf"
            ),
            Share.from_mnemonic(
                "academic agency beard marathon display oasis crowd wits rhyme eclipse problem pecan security main license exclude editor fumes salary deploy"
            ),
            Share.from_mnemonic(
                "academic agency beard merit distance welfare survive sniff damage husband knife evening gross garlic check result extend estate agency destroy"
            ),
        ],
        [
            Share.from_mnemonic(
                "academic agency ceramic learn academic academic academic academic academic academic academic academic academic academic academic academic academic zero laundry presence"
            ),
            Share.from_mnemonic(
                "academic agency ceramic lips blind wireless process scramble military lecture diploma nylon birthday talent deal wealthy briefing edge geology scandal"
            ),
            Share.from_mnemonic(
                "academic agency ceramic luxury drove vampire criminal idea damage husband knife evening gross garlic check result extend work keyboard priority"
            ),
            Share.from_mnemonic(
                "academic agency ceramic march counter ancestor lizard railroad river usual estate software improve river behavior emperor envy elevator genre scholar"
            ),
            Share.from_mnemonic(
                "academic agency ceramic method change magazine exhaust forecast priority fused pink presence demand webcam violence visual crowd tendency declare coastal"
            ),
            Share.from_mnemonic(
                "academic agency ceramic mortgage desert imply tenant package dream syndrome paid diet clothes cluster scout average depend fused cubic express"
            ),
            Share.from_mnemonic(
                "academic agency ceramic nervous calcium item graduate critical license darkness spine total fiber numb starting eraser justice that deny clothes"
            ),
        ],
    ]
    assert mnemonics_extend_b[0] == mnemonics_extend_a[0]
    assert mnemonics_extend_b[1][:3] == mnemonics_extend_a[1]
    assert mnemonics_extend_b[2][:5] == mnemonics_extend_a[2]

    # Note that both SLIP-39 Mnemonics are "extendable", regardless of the value of the extendable
    # option when created.  So long as the caller only alters the number of shares in a group (and
    # not the group count or threshold, or the group member threshold required), you can create
    # additional group members usable to recover the original EncryptedMasterSecret.

    # We'll expect exactly one recovery for this set of mnemonic shares.  Note that we're recovering
    # a "non-extendable" EncryptedMasterSecret here, using output from two split_ems calls with
    # different group member counts, but identical thresholds:
    ems, groups = next(
        shamir.group_ems_mnemonics(mnemonics_nonext_a[0] + mnemonics_nonext_b[1][:-2])
    )
    # print( f"Recovered {ems} using: {json.dumps( groups, indent=4, default=str )}" )
    assert ems.decrypt(b"TREZOR") == MS
    assert groups == {
        0: [
            Share.from_mnemonic(
                "academic acid acrobat leader civil gross counter dictate fancy findings lair freshman kind justice apart quiet lunch short vitamins painting"
            )
        ],
        1: [
            Share.from_mnemonic(
                "academic acid beard lungs center injury academic pupal hand surface volume have smart hormone wealthy echo capture year browser material"
            ),
            Share.from_mnemonic(
                "academic acid beard leaf desktop crowd erode vegan season warmth warn craft ceramic picture wrote depend radar result dream that"
            ),
        ],
    }

    # Here, we'll recover both unique EncryptedMasterSecret values with unique common_parameters
    # from the pool of all available mnemonics.  This is the super-power of group_ems_mnemonics; it
    # will process arbitrary pools of Mnemonics, identify the unique common_parameters, and then
    # iterate over all combinations and cartesion products of available share groups to try to
    # recover any SLIP-39 encoded EncryptedMasterSecret values available.  It will ignore any
    # invalid, redundant or incomplete mnemonics.
    recovered = []
    for ems, groups in shamir.group_ems_mnemonics(
        sum(
            mnemonics_nonext_a
            + mnemonics_nonext_b
            + mnemonics_extend_a
            + mnemonics_extend_b,
            [],
        )
    ):
        recovered.append(ems)
    assert len(recovered) == 2
    assert all(ems.decrypt(b"TREZOR") == MS for ems in recovered)
