#
# Copyright (c) 2018 Andrew R. Kozlik
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

import hmac
import itertools
import secrets
from dataclasses import dataclass
from typing import (
    Any,
    Dict,
    Iterable,
    Iterator,
    List,
    NamedTuple,
    Sequence,
    Set,
    Tuple,
    Union,
)

from . import cipher
from .constants import (
    DIGEST_INDEX,
    DIGEST_LENGTH_BYTES,
    GROUP_PREFIX_LENGTH_WORDS,
    ID_EXP_LENGTH_WORDS,
    ID_LENGTH_BITS,
    MAX_SHARE_COUNT,
    MIN_STRENGTH_BITS,
    SECRET_INDEX,
)
from .share import Share, ShareCommonParameters, ShareGroupParameters
from .utils import MnemonicError, bits_to_bytes


class RawShare(NamedTuple):
    x: int
    data: bytes


class ShareGroup:
    def __init__(self) -> None:
        self.shares: Set[Share] = set()

    def __iter__(self) -> Iterator[Share]:
        return iter(self.shares)

    def __len__(self) -> int:
        return len(self.shares)

    def __bool__(self) -> bool:
        return bool(self.shares)

    def __contains__(self, obj: Any) -> bool:
        return obj in self.shares

    def add(self, share: Share) -> None:
        if self.shares and self.group_parameters() != share.group_parameters():
            fields = zip(
                ShareGroupParameters._fields,
                self.group_parameters(),
                share.group_parameters(),
            )
            mismatch = next(name for name, x, y in fields if x != y)
            raise MnemonicError(
                f"Invalid set of mnemonics. The {mismatch} parameters don't match."
            )

        self.shares.add(share)

    def to_raw_shares(self) -> List[RawShare]:
        return [RawShare(s.index, s.value) for s in self.shares]

    def get_minimal_group(self) -> "ShareGroup":
        return next(self.get_possible_groups())

    def get_possible_groups(self) -> "ShareGroup":
        if not self.is_complete():
            raise MnemonicError(
                f"Incomplete group of mnemonics; {len(self.shares)} provided of {self.member_threshold()} required."
            )
        shares = list(self.shares)
        for combo in itertools.combinations(
            range(len(shares)), self.member_threshold()
        ):
            group = ShareGroup()
            group.shares = set(shares[i] for i in combo)
            yield group

    def common_parameters(self) -> ShareCommonParameters:
        return next(iter(self.shares)).common_parameters()

    def group_parameters(self) -> ShareGroupParameters:
        return next(iter(self.shares)).group_parameters()

    def member_threshold(self) -> int:
        return next(iter(self.shares)).member_threshold

    def is_complete(self) -> bool:
        if self.shares:
            return len(self.shares) >= self.member_threshold()
        else:
            return False


@dataclass(frozen=True)
class EncryptedMasterSecret:
    identifier: int
    extendable: bool
    iteration_exponent: int
    ciphertext: bytes

    @classmethod
    def from_master_secret(
        cls,
        master_secret: bytes,
        passphrase: bytes,
        identifier: int,
        extendable: bool,
        iteration_exponent: int,
    ) -> "EncryptedMasterSecret":
        ciphertext = cipher.encrypt(
            master_secret, passphrase, iteration_exponent, identifier, extendable
        )
        return EncryptedMasterSecret(
            identifier, extendable, iteration_exponent, ciphertext
        )

    def decrypt(self, passphrase: bytes) -> bytes:
        return cipher.decrypt(
            self.ciphertext,
            passphrase,
            self.iteration_exponent,
            self.identifier,
            self.extendable,
        )


RANDOM_BYTES = secrets.token_bytes
"""Source of random bytes. Can be overriden for deterministic testing."""


def _precompute_exp_log() -> Tuple[List[int], List[int]]:
    exp = [0 for i in range(255)]
    log = [0 for i in range(256)]

    poly = 1
    for i in range(255):
        exp[i] = poly
        log[poly] = i

        # Multiply poly by the polynomial x + 1.
        poly = (poly << 1) ^ poly

        # Reduce poly by x^8 + x^4 + x^3 + x + 1.
        if poly & 0x100:
            poly ^= 0x11B

    return exp, log


EXP_TABLE, LOG_TABLE = _precompute_exp_log()


def _interpolate(shares: Sequence[RawShare], x: int) -> bytes:
    """
    Returns f(x) given the Shamir shares (x_1, f(x_1)), ... , (x_k, f(x_k)).
    :param shares: The Shamir shares.
    :type shares: A list of pairs (x_i, y_i), where x_i is an integer and y_i is an array of
        bytes representing the evaluations of the polynomials in x_i.
    :param int x: The x coordinate of the result.
    :return: Evaluations of the polynomials in x.
    :rtype: Array of bytes.
    """

    x_coordinates = set(share.x for share in shares)

    if len(x_coordinates) != len(shares):
        raise MnemonicError("Invalid set of shares. Share indices must be unique.")

    share_value_lengths = set(len(share.data) for share in shares)
    if len(share_value_lengths) != 1:
        raise MnemonicError(
            "Invalid set of shares. All share values must have the same length."
        )

    if x in x_coordinates:
        for share in shares:
            if share.x == x:
                return share.data

    # Logarithm of the product of (x_i - x) for i = 1, ... , k.
    log_prod = sum(LOG_TABLE[share.x ^ x] for share in shares)

    result = bytes(share_value_lengths.pop())
    for share in shares:
        # The logarithm of the Lagrange basis polynomial evaluated at x.
        log_basis_eval = (
            log_prod
            - LOG_TABLE[share.x ^ x]
            - sum(LOG_TABLE[share.x ^ other.x] for other in shares)
        ) % 255

        result = bytes(
            intermediate_sum
            ^ (
                EXP_TABLE[(LOG_TABLE[share_val] + log_basis_eval) % 255]
                if share_val != 0
                else 0
            )
            for share_val, intermediate_sum in zip(share.data, result)
        )

    return result


def _create_digest(random_data: bytes, shared_secret: bytes) -> bytes:
    return hmac.new(random_data, shared_secret, "sha256").digest()[:DIGEST_LENGTH_BYTES]


def _split_secret(
    threshold: int, share_count: int, shared_secret: bytes
) -> List[RawShare]:
    if threshold < 1:
        raise ValueError("The requested threshold must be a positive integer.")

    if threshold > share_count:
        raise ValueError(
            "The requested threshold must not exceed the number of shares."
        )

    if share_count > MAX_SHARE_COUNT:
        raise ValueError(
            f"The requested number of shares must not exceed {MAX_SHARE_COUNT}."
        )

    # If the threshold is 1, then the digest of the shared secret is not used.
    if threshold == 1:
        return [RawShare(i, shared_secret) for i in range(share_count)]

    random_share_count = threshold - 2

    shares = [
        RawShare(i, RANDOM_BYTES(len(shared_secret))) for i in range(random_share_count)
    ]

    random_part = RANDOM_BYTES(len(shared_secret) - DIGEST_LENGTH_BYTES)
    digest = _create_digest(random_part, shared_secret)

    base_shares = shares + [
        RawShare(DIGEST_INDEX, digest + random_part),
        RawShare(SECRET_INDEX, shared_secret),
    ]

    for i in range(random_share_count, share_count):
        shares.append(RawShare(i, _interpolate(base_shares, i)))

    return shares


def _recover_secret(threshold: int, shares: Sequence[RawShare]) -> bytes:
    # If the threshold is 1, then the digest of the shared secret is not used.
    if threshold == 1:
        return next(iter(shares)).data

    shared_secret = _interpolate(shares, SECRET_INDEX)
    digest_share = _interpolate(shares, DIGEST_INDEX)
    digest = digest_share[:DIGEST_LENGTH_BYTES]
    random_part = digest_share[DIGEST_LENGTH_BYTES:]

    if digest != _create_digest(random_part, shared_secret):
        raise MnemonicError("Invalid digest of the shared secret.")

    return shared_secret


def group_ems_mnemonics(
    mnemonics: Iterable[Union[str, Share]], strict: bool = False
) -> Sequence[Tuple[EncryptedMasterSecret, Dict[int, Sequence[Share]]]]:
    """Attempt to yield a sequence of unique decoded EncryptedMasterSecret, and the dictionary of group
    indices -> set(<Share>) used to recover each SLIP-39 encoded encrypted seed.

    This is difficult to do externally, because it requires partially decoding the mnemonics to
    deduce the group parameters, and then select a subset of the mnemonics to satisfy them.

    Since extra mnemonics (some perhaps with errors) may be supplied, we may need to produce
    combinations until we've eliminated the erroneous one(s).  Then, if someone mistakenly collects
    groups of incompatible mnemonics (for example, with the same identifier and group numbers, but
    from a different original master secret, or from an attacker supplying decoy mnenonics), we'll
    supply all possible combinations of the available groups to aid recovery of the master secret.

    Even if groups of mnemonics from multiple SLIP-39 encodings are collected, aid the caller in
    recovery of any/all of them.

    Ignores invalid Mnemonics and absence of a recovered secret unless strict is specified.

    """
    # Eliminate any obviously flawed Mnemonics, group by distinct common, then group parameters
    common_params: Dict[
        ShareCommonParameters, Dict[ShareGroupParameters, ShareGroup]
    ] = {}
    for share in mnemonics:
        try:
            if isinstance(share, str):
                share = Share.from_mnemonic(share)
        except Exception:
            if strict:
                raise
        else:
            # We will cluster shares by distinct common_parameters (identifier, extendable,
            # iteration_exponent, group_threshold, group_count), then by group_parameters.  This allows
            # us to combine shares from original or extended mnemonics generated later, and attempt to
            # recover mixed incompatible SLIP-39 groups.
            common_params.setdefault(
                share.common_parameters(), {}  # incompatible SLIP-39 configurations
            ).setdefault(
                share.group_parameters(), ShareGroup()  # compatible mnemonics
            ).add(
                share  # Cannot fail
            )

    # Now that we have isolated the distinct share groups, it's time to see what we can recover.
    # How many different Mnemonic sets are we possibly dealing with?  In addition to identifier, we
    # have group count, extended, etc.  Allow multiple independent sets of mnemonics.  Our task is
    # to support the user in recovering their master seeds, however many they may have, or however
    # the mnemonics may have been mixed.

    # Try every minimum viable subset of groups of length group_threshold, and for each group all
    # minimum viable subsets of provided mnemonics.  We want to support recovery, even if invalid
    # Mnemonics have been provided for a group, and if incompatible groups (same identifier and
    # other common parameters but for a different master seed, or mixed groups) were provided.
    recovered: Set[EncryptedMasterSecret] = set()
    for distinct, sharegroups in common_params.items():
        # Go through each of the available groups, identifying all available recoverable group
        # secrets.  Once a subset of mnemonics is used, discard them and see if any other secrets
        # are recoverable; multiple different (or decoy) SLIP-39 groups w/ the same common
        # parameters could have been provided.
        possibles: Dict[int, Dict[RawShare, ShareGroup]] = {}
        for groupings, sharegroup in sharegroups.items():
            if not sharegroup.is_complete():
                continue
            for shareminimal in sharegroup.get_possible_groups():
                try:
                    rawshare = RawShare(
                        groupings.group_index,
                        _recover_secret(
                            groupings.member_threshold, shareminimal.to_raw_shares()
                        ),
                    )
                except Exception:
                    pass
                else:
                    possibles.setdefault(
                        rawshare.x, {}  # by SLIP-39 group indices
                    ).setdefault(
                        rawshare, shareminimal  # by recovered group RawShare
                    )
                    sharegroup.shares -= shareminimal.shares
                    break

        # We now have all resolved available group indices x and their decoded group secret from
        # RawGroup(x,data), and the first set of Mnemonics that resulted in each.  We want to now
        # recover all combinations of these groups that lead to different SLIP-39 encrypted master
        # secrets.  Since we can't know which combinations of group secrets could lead to a
        # successful SLIP-39 decoding, we'll try every minimal combination of group indices
        # available.
        def ems_rawshares():
            """We have a minimal subset of the available groups indices w/ decoded secrets.
            Produce the cartesian product of groups g0, g1, ..., gN.  The possibles: {x: ->
            {RawGroup: ShareGroup}} gives us a sequence of RawGroup(s) for group index x.

            This would (inefficiently) find all combinations of available mnemonics the could be
            combined to recover an encrypted master secret -- but, the caller should remove
            the used RawShares from possibles before re-invoking.

            """
            for subgroups in itertools.combinations(
                sorted(possibles), distinct.group_threshold
            ):
                for rawshares in itertools.product(
                    *(possibles[gn].keys() for gn in subgroups)
                ):
                    try:
                        ems = EncryptedMasterSecret(
                            distinct.identifier,
                            distinct.extendable,
                            distinct.iteration_exponent,
                            _recover_secret(distinct.group_threshold, rawshares),
                        )
                        return ems, rawshares
                    except Exception:
                        pass
            # No more encrypted master secrets; return the remaining (unused) RawShares
            return None, sum((list(possibles[gn]) for gn in possibles), [])

        # Yields every encrypted master secret recovered, and the group indices and set of Share
        # mnemonics used to recover it.  This will be a minimal subset of the groups and mnemonics
        # supplied.
        while len(possibles) >= distinct.group_threshold:
            ems, rawshares = ems_rawshares()
            # Remove all {RawShare: ShareGroup} used from possibles, and return as {group#:
            # Sequence[Share]} Each group's set's shares are ordered by index, for testing
            # repeatability and ordering compatibility with other ..._ems functions.
            groups = {
                rawshare.x: sorted(
                    possibles[rawshare.x].pop(rawshare).shares, key=lambda s: s.index
                )
                for rawshare in rawshares
            }
            for x in list(possibles):
                if not possibles[x]:
                    possibles.pop(x)
            if ems and ems not in recovered:
                yield ems, groups
                recovered.add(ems)

    if strict and not recovered:
        raise MnemonicError("Invalid set of mnemonics; No encoded secret found")


def decode_mnemonics(mnemonics: Iterable[str]) -> Dict[int, ShareGroup]:
    common_params: Set[ShareCommonParameters] = set()
    groups: Dict[int, ShareGroup] = {}
    for mnemonic in mnemonics:
        share = Share.from_mnemonic(mnemonic)
        common_params.add(share.common_parameters())
        group = groups.setdefault(share.group_index, ShareGroup())
        group.add(share)

    if len(common_params) != 1:
        raise MnemonicError(
            "Invalid set of mnemonics. "
            f"All mnemonics must begin with the same {ID_EXP_LENGTH_WORDS} words, "
            "must have the same group threshold and the same group count."
        )

    return groups


def split_ems(
    group_threshold: int,
    groups: Sequence[Tuple[int, int]],
    encrypted_master_secret: EncryptedMasterSecret,
) -> List[List[Share]]:
    """
    Split an Encrypted Master Secret into mnemonic shares.

    This function is a counterpart to `recover_ems`, and it is used as a subroutine in
    `generate_mnemonics`. The input is an *already encrypted* Master Secret (EMS), so it
    is possible to encrypt the Master Secret in advance and perform the splitting later.

    :param group_threshold: The number of groups required to reconstruct the master secret.
    :param groups: A list of (member_threshold, member_count) pairs for each group, where member_count
        is the number of shares to generate for the group and member_threshold is the number of members required to
        reconstruct the group secret.
    :param encrypted_master_secret: The encrypted master secret to split.
    :return: List of groups of mnemonics.
    """
    if len(encrypted_master_secret.ciphertext) * 8 < MIN_STRENGTH_BITS:
        raise ValueError(
            "The length of the master secret must be "
            f"at least {bits_to_bytes(MIN_STRENGTH_BITS)} bytes."
        )

    if group_threshold > len(groups):
        raise ValueError(
            "The requested group threshold must not exceed the number of groups."
        )

    if any(
        member_threshold == 1 and member_count > 1
        for member_threshold, member_count in groups
    ):
        raise ValueError(
            "Creating multiple member shares with member threshold 1 is not allowed. "
            "Use 1-of-1 member sharing instead."
        )

    group_shares = _split_secret(
        group_threshold, len(groups), encrypted_master_secret.ciphertext
    )

    return [
        [
            Share(
                encrypted_master_secret.identifier,
                encrypted_master_secret.extendable,
                encrypted_master_secret.iteration_exponent,
                group_index,
                group_threshold,
                len(groups),
                member_index,
                member_threshold,
                value,
            )
            for member_index, value in _split_secret(
                member_threshold, member_count, group_secret
            )
        ]
        for (member_threshold, member_count), (group_index, group_secret) in zip(
            groups, group_shares
        )
    ]


def _random_identifier() -> int:
    """Returns a random identifier with the given bit length."""
    identifier = int.from_bytes(RANDOM_BYTES(bits_to_bytes(ID_LENGTH_BITS)), "big")
    return identifier & ((1 << ID_LENGTH_BITS) - 1)


def generate_mnemonics(
    group_threshold: int,
    groups: Sequence[Tuple[int, int]],
    master_secret: bytes,
    passphrase: bytes = b"",
    extendable: bool = True,
    iteration_exponent: int = 1,
) -> List[List[str]]:
    """
    Split a master secret into mnemonic shares using Shamir's secret sharing scheme.

    The supplied Master Secret is encrypted by the passphrase (empty passphrase is used
    if none is provided) and split into a set of mnemonic shares.

    This is the user-friendly method to back up a pre-existing secret with the Shamir
    scheme, optionally protected by a passphrase.

    :param group_threshold: The number of groups required to reconstruct the master secret.
    :param groups: A list of (member_threshold, member_count) pairs for each group, where member_count
        is the number of shares to generate for the group and member_threshold is the number of members required to
        reconstruct the group secret.
    :param master_secret: The master secret to split.
    :param passphrase: The passphrase used to encrypt the master secret.
    :param int iteration_exponent: The encryption iteration exponent.
    :return: List of groups mnemonics.
    """
    if not all(32 <= c <= 126 for c in passphrase):
        raise ValueError(
            "The passphrase must contain only printable ASCII characters (code points 32-126)."
        )

    identifier = _random_identifier()
    encrypted_master_secret = EncryptedMasterSecret.from_master_secret(
        master_secret, passphrase, identifier, extendable, iteration_exponent
    )
    grouped_shares = split_ems(group_threshold, groups, encrypted_master_secret)
    return [[share.mnemonic() for share in group] for group in grouped_shares]


def recover_ems(groups: Dict[int, ShareGroup]) -> EncryptedMasterSecret:
    """
    Combine shares, recover metadata and the Encrypted Master Secret.

    This function is a counterpart to `split_ems`, and it is used as a subroutine in
    `combine_mnemonics`. It returns the EMS itself and data required for its decryption,
    except for the passphrase. It is thus possible to defer decryption of the Master
    Secret to a later time.

    Requires a minimal group_threshold subset of groups, and each group must be a minimal
    member_threshold of the group's mnemonics.

    :param groups: Set of shares classified into groups.
    :return: Encrypted Master Secret
    """

    if not groups:
        raise MnemonicError("The set of shares is empty.")

    params = next(iter(groups.values())).common_parameters()

    if len(groups) < params.group_threshold:
        raise MnemonicError(
            "Insufficient number of mnemonic groups. "
            f"The required number of groups is {params.group_threshold}."
        )

    if len(groups) != params.group_threshold:
        raise MnemonicError(
            "Wrong number of mnemonic groups. "
            f"Expected {params.group_threshold} groups, "
            f"but {len(groups)} were provided."
        )

    for group in groups.values():
        if len(group) != group.member_threshold():
            share_words = next(iter(group)).words()
            prefix = " ".join(share_words[:GROUP_PREFIX_LENGTH_WORDS])
            raise MnemonicError(
                "Wrong number of mnemonics. "
                f'Expected {group.member_threshold()} mnemonics starting with "{prefix} ...", '
                f"but {len(group)} were provided."
            )

    group_shares = [
        RawShare(
            group_index,
            _recover_secret(group.member_threshold(), group.to_raw_shares()),
        )
        for group_index, group in groups.items()
    ]

    ciphertext = _recover_secret(params.group_threshold, group_shares)
    return EncryptedMasterSecret(
        params.identifier, params.extendable, params.iteration_exponent, ciphertext
    )


def combine_mnemonics(mnemonics: Iterable[str], passphrase: bytes = b"") -> bytes:
    """
    Combine mnemonic shares to obtain the master secret which was previously split
    using Shamir's secret sharing scheme.

    This is the user-friendly method to recover a backed-up secret optionally protected
    by a passphrase.

    :param mnemonics: List of mnemonics.
    :param passphrase: The passphrase used to encrypt the master secret.
    :return: The master secret.
    """

    if not mnemonics:
        raise MnemonicError("The list of mnemonics is empty.")

    groups = decode_mnemonics(mnemonics)
    encrypted_master_secret = recover_ems(groups)
    return encrypted_master_secret.decrypt(passphrase)
