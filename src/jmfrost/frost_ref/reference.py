# -*- coding: utf-8 -*-

# BIP FROST Signing reference implementation
#
# It's worth noting that many functions, types, and exceptions were directly
# copied or modified from the MuSig2 (BIP 327) reference code, found at:
# https://github.com/bitcoin/bips/blob/master/bip-0327/reference.py
#
# WARNING: This implementation is for demonstration purposes only and _not_ to
# be used in production environments. The code is vulnerable to timing attacks,
# for example.

from typing import Any, List, Optional, Tuple, NewType, NamedTuple
import itertools
import secrets
import time

from .utils.bip340 import *

PlainPk = NewType('PlainPk', bytes)
XonlyPk = NewType('XonlyPk', bytes)

# There are two types of exceptions that can be raised by this implementation:
#   - ValueError for indicating that an input doesn't conform to some function
#     precondition (e.g. an input array is the wrong length, a serialized
#     representation doesn't have the correct format).
#   - InvalidContributionError for indicating that a signer (or the
#     aggregator) is misbehaving in the protocol.
#
# Assertions are used to (1) satisfy the type-checking system, and (2) check for
# inconvenient events that can't happen except with negligible probability (e.g.
# output of a hash function is 0) and can't be manually triggered by any
# signer.

# This exception is raised if a party (signer or nonce aggregator) sends invalid
# values. Actual implementations should not crash when receiving invalid
# contributions. Instead, they should hold the offending party accountable.
class InvalidContributionError(Exception):
    def __init__(self, signer_id, contrib):
        # participant identifier of the signer who sent the invalid value
        self.id = signer_id
        # contrib is one of "pubkey", "pubnonce", "aggnonce", or "psig".
        self.contrib = contrib

infinity = None

def xbytes(P: Point) -> bytes:
    return bytes_from_int(x(P))

def cbytes(P: Point) -> bytes:
    a = b'\x02' if has_even_y(P) else b'\x03'
    return a + xbytes(P)

def cbytes_ext(P: Optional[Point]) -> bytes:
    if is_infinite(P):
        return (0).to_bytes(33, byteorder='big')
    assert P is not None
    return cbytes(P)

def point_negate(P: Optional[Point]) -> Optional[Point]:
    if P is None:
        return P
    return (x(P), p - y(P))

def cpoint(x: bytes) -> Point:
    if len(x) != 33:
        raise ValueError('x is not a valid compressed point.')
    P = lift_x(x[1:33])
    if P is None:
        raise ValueError('x is not a valid compressed point.')
    if x[0] == 2:
        return P
    elif x[0] == 3:
        P = point_negate(P)
        assert P is not None
        return P
    else:
        raise ValueError('x is not a valid compressed point.')

def cpoint_ext(x: bytes) -> Optional[Point]:
    if x == (0).to_bytes(33, 'big'):
        return None
    else:
        return cpoint(x)

def int_ids(lst: List[bytes]) -> List[int]:
    res = []
    for x in lst:
        id_ = int_from_bytes(x)
        #todo: add check for < max_participants?
        if not 1 <= id_ < n:
            raise ValueError('x is not a valid participant identifier.')
        res.append(id_)
    return res

# Return the plain public key corresponding to a given secret key
def individual_pk(seckey: bytes) -> PlainPk:
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, d0)
    assert P is not None
    return PlainPk(cbytes(P))

def derive_interpolating_value_internal(L: List[int], x_i: int) -> int:
    num, deno = 1, 1
    for x_j in L:
        if x_j == x_i:
            continue
        num *= x_j
        deno *= (x_j - x_i)
    return num * pow(deno, n - 2, n) % n

def derive_interpolating_value(ids: List[bytes], my_id: bytes) -> int:
    if not my_id in ids:
        raise ValueError('The signer\'s id must be present in the participant identifier list.')
    if not all(ids.count(my_id) <= 1 for my_id in ids):
        raise ValueError('The participant identifier list must contain unique elements.')
    #todo: turn this into raise ValueError?
    assert 1 <= int_from_bytes(my_id) < n
    integer_ids = int_ids(ids)
    return derive_interpolating_value_internal(integer_ids, int_from_bytes(my_id))

def check_pubshares_correctness(secshares: List[bytes], pubshares: List[PlainPk]) -> bool:
    assert len(secshares) == len(pubshares)
    for secshare, pubshare in zip(secshares, pubshares):
        if not individual_pk(secshare) == pubshare:
            return False
    return True

def check_group_pubkey_correctness(min_participants: int, group_pk: PlainPk, ids: List[bytes], pubshares: List[PlainPk]) -> bool:
    assert len(ids) == len(pubshares)
    assert len(ids) >= min_participants

    max_participants = len(ids)
    # loop through all possible number of signers
    for signer_count in range(min_participants, max_participants + 1):
        # loop through all possible signer sets with length `signer_count`
        for signer_set in itertools.combinations(zip(ids, pubshares), signer_count):
            signer_ids = [pid for pid, pubshare in signer_set]
            signer_pubshares = [pubshare for pid, pubshare in signer_set]
            expected_pk = derive_group_pubkey(signer_pubshares, signer_ids)
            if expected_pk != group_pk:
                return False
    return True

def check_frost_key_compatibility(max_participants: int, min_participants: int, group_pk: PlainPk, ids: List[bytes], secshares: List[bytes], pubshares: List[PlainPk]) -> bool:
    if not max_participants >= min_participants > 1:
        return False
    if not len(ids) == len(secshares) == len(pubshares) == max_participants:
        return False
    pubshare_check = check_pubshares_correctness(secshares, pubshares)
    group_pk_check = check_group_pubkey_correctness(min_participants, group_pk, ids, pubshares)
    return pubshare_check and group_pk_check

TweakContext = NamedTuple('TweakContext', [('Q', Point),
                                           ('gacc', int),
                                           ('tacc', int)])
AGGREGATOR_ID = b'aggregator'

def get_xonly_pk(tweak_ctx: TweakContext) -> XonlyPk:
    Q, _, _ = tweak_ctx
    return XonlyPk(xbytes(Q))

def get_plain_pk(tweak_ctx: TweakContext) -> PlainPk:
    Q, _, _ = tweak_ctx
    return PlainPk(cbytes(Q))

#nit: switch the args ordering
def derive_group_pubkey(pubshares: List[PlainPk], ids: List[bytes]) -> PlainPk:
    assert len(pubshares) == len(ids)
    assert AGGREGATOR_ID not in ids
    Q = infinity
    for my_id, pubshare in zip(ids, pubshares):
        try:
            X_i = cpoint(pubshare)
        except ValueError:
            raise InvalidContributionError(int_from_bytes(my_id), "pubshare")
        lam_i = derive_interpolating_value(ids, my_id)
        Q = point_add(Q, point_mul(X_i, lam_i))
    # Q is not the point at infinity except with negligible probability.
    assert(Q is not infinity)
    return PlainPk(cbytes(Q))

def tweak_ctx_init(pubshares: List[PlainPk], ids: List[bytes]) -> TweakContext:
    group_pk = derive_group_pubkey(pubshares, ids)
    Q = cpoint(group_pk)
    gacc = 1
    tacc = 0
    return TweakContext(Q, gacc, tacc)

def apply_tweak(tweak_ctx: TweakContext, tweak: bytes, is_xonly: bool) -> TweakContext:
    if len(tweak) != 32:
        raise ValueError('The tweak must be a 32-byte array.')
    Q, gacc, tacc = tweak_ctx
    if is_xonly and not has_even_y(Q):
        g = n - 1
    else:
        g = 1
    t = int_from_bytes(tweak)
    if t >= n:
        raise ValueError('The tweak must be less than n.')
    Q_ = point_add(point_mul(Q, g), point_mul(G, t))
    if Q_ is None:
        raise ValueError('The result of tweaking cannot be infinity.')
    gacc_ = g * gacc % n
    tacc_ = (t + g * tacc) % n
    return TweakContext(Q_, gacc_, tacc_)

def bytes_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def nonce_hash(rand: bytes, pubshare: PlainPk, group_pk: XonlyPk, i: int, msg_prefixed: bytes, extra_in: bytes) -> int:
    buf = b''
    buf += rand
    buf += len(pubshare).to_bytes(1, 'big')
    buf += pubshare
    buf += len(group_pk).to_bytes(1, 'big')
    buf += group_pk
    buf += msg_prefixed
    buf += len(extra_in).to_bytes(4, 'big')
    buf += extra_in
    buf += i.to_bytes(1, 'big')
    return int_from_bytes(tagged_hash('FROST/nonce', buf))

def nonce_gen_internal(rand_: bytes, secshare: Optional[bytes], pubshare: Optional[PlainPk], group_pk: Optional[XonlyPk], msg: Optional[bytes], extra_in: Optional[bytes]) -> Tuple[bytearray, bytes]:
    if secshare is not None:
        rand = bytes_xor(secshare, tagged_hash('FROST/aux', rand_))
    else:
        rand = rand_
    if pubshare is None:
        pubshare = PlainPk(b'')
    if group_pk is None:
        group_pk = XonlyPk(b'')
    if msg is None:
        msg_prefixed = b'\x00'
    else:
        msg_prefixed = b'\x01'
        msg_prefixed += len(msg).to_bytes(8, 'big')
        msg_prefixed += msg
    if extra_in is None:
        extra_in = b''
    k_1 = nonce_hash(rand, pubshare, group_pk, 0, msg_prefixed, extra_in) % n
    k_2 = nonce_hash(rand, pubshare, group_pk, 1, msg_prefixed, extra_in) % n
    # k_1 == 0 or k_2 == 0 cannot occur except with negligible probability.
    assert k_1 != 0
    assert k_2 != 0
    R_s1 = point_mul(G, k_1)
    R_s2 = point_mul(G, k_2)
    assert R_s1 is not None
    assert R_s2 is not None
    pubnonce = cbytes(R_s1) + cbytes(R_s2)
    # use mutable `bytearray` since secnonce need to be replaced with zeros during signing.
    secnonce = bytearray(bytes_from_int(k_1) + bytes_from_int(k_2))
    return secnonce, pubnonce

#think: can msg & extra_in be of any length here?
#think: why doesn't musig2 ref code check for `pk` length here?
def nonce_gen(secshare: Optional[bytes], pubshare: Optional[PlainPk], group_pk: Optional[XonlyPk], msg: Optional[bytes], extra_in: Optional[bytes]) -> Tuple[bytearray, bytes]:
    if secshare is not None and len(secshare) != 32:
        raise ValueError('The optional byte array secshare must have length 32.')
    if pubshare is not None and len(pubshare) != 33:
        raise ValueError('The optional byte array pubshare must have length 33.')
    if group_pk is not None and len(group_pk) != 32:
        raise ValueError('The optional byte array group_pk must have length 32.')
    # bench: will adding individual_pk(secshare) == pubshare check, increase the execution time significantly?
    rand_ = secrets.token_bytes(32)
    return nonce_gen_internal(rand_, secshare, pubshare, group_pk, msg, extra_in)

def nonce_agg(pubnonces: List[bytes], ids: List[bytes]) -> bytes:
    if len(pubnonces) != len(ids):
        raise ValueError('The pubnonces and ids arrays must have the same length.')
    aggnonce = b''
    for j in (1, 2):
        R_j = infinity
        for my_id_, pubnonce in zip(ids, pubnonces):
            try:
                R_ij = cpoint(pubnonce[(j-1)*33:j*33])
            except ValueError:
                my_id = int_from_bytes(my_id_) if my_id_ != AGGREGATOR_ID else my_id_
                raise InvalidContributionError(my_id, "pubnonce")
            R_j = point_add(R_j, R_ij)
        aggnonce += cbytes_ext(R_j)
    return aggnonce

SessionContext = NamedTuple('SessionContext', [('aggnonce', bytes),
                                               ('identifiers', List[bytes]),
                                               ('pubshares', List[PlainPk]),
                                               ('tweaks', List[bytes]),
                                               ('is_xonly', List[bool]),
                                               ('msg', bytes)])

def group_pubkey_and_tweak(pubshares: List[PlainPk], ids: List[bytes], tweaks: List[bytes], is_xonly: List[bool]) -> TweakContext:
    if len(pubshares) != len(ids):
        raise ValueError('The pubshares and ids arrays must have the same length.')
    if len(tweaks) != len(is_xonly):
        raise ValueError('The tweaks and is_xonly arrays must have the same length.')
    tweak_ctx = tweak_ctx_init(pubshares, ids)
    v = len(tweaks)
    for i in range(v):
        tweak_ctx = apply_tweak(tweak_ctx, tweaks[i], is_xonly[i])
    return tweak_ctx

def get_session_values(session_ctx: SessionContext) -> Tuple[Point, int, int, int, Point, int]:
    (aggnonce, ids, pubshares, tweaks, is_xonly, msg) = session_ctx
    Q, gacc, tacc = group_pubkey_and_tweak(pubshares, ids, tweaks, is_xonly)
    # sort the ids before serializing because ROAST paper considers them as a set
    concat_ids = b''.join(sorted(ids))
    b = int_from_bytes(tagged_hash('FROST/noncecoef', concat_ids + aggnonce + xbytes(Q) + msg)) % n
    try:
        R_1 = cpoint_ext(aggnonce[0:33])
        R_2 = cpoint_ext(aggnonce[33:66])
    except ValueError:
        # Nonce aggregator sent invalid nonces
        raise InvalidContributionError(None, "aggnonce")
    R_ = point_add(R_1, point_mul(R_2, b))
    R = R_ if not is_infinite(R_) else G
    assert R is not None
    e = int_from_bytes(tagged_hash('BIP0340/challenge', xbytes(R) + xbytes(Q) + msg)) % n
    return (Q, gacc, tacc, b, R, e)

def get_session_interpolating_value(session_ctx: SessionContext, my_id: bytes) -> int:
    (_, ids, _, _, _, _) = session_ctx
    return derive_interpolating_value(ids, my_id)

def session_has_signer_pubshare(session_ctx: SessionContext, pubshare: bytes) -> bool:
    (_, _, pubshares_list, _, _, _) = session_ctx
    return pubshare in pubshares_list

def sign(secnonce: bytearray, secshare: bytes, my_id: bytes, session_ctx: SessionContext) -> bytes:
    # do we really need the below check?
    # add test vector for this check if confirmed
    if not 0 < int_from_bytes(my_id) < n:
        raise ValueError('The signer\'s participant identifier is out of range')
    (Q, gacc, _, b, R, e) = get_session_values(session_ctx)
    k_1_ = int_from_bytes(secnonce[0:32])
    k_2_ = int_from_bytes(secnonce[32:64])
    # Overwrite the secnonce argument with zeros such that subsequent calls of
    # sign with the same secnonce raise a ValueError.
    secnonce[:] = bytearray(b'\x00'*64)
    if not 0 < k_1_ < n:
        raise ValueError('first secnonce value is out of range.')
    if not 0 < k_2_ < n:
        raise ValueError('second secnonce value is out of range.')
    k_1 = k_1_ if has_even_y(R) else n - k_1_
    k_2 = k_2_ if has_even_y(R) else n - k_2_
    d_ = int_from_bytes(secshare)
    if not 0 < d_ < n:
        raise ValueError('The signer\'s secret share value is out of range.')
    P = point_mul(G, d_)
    assert P is not None
    pubshare = cbytes(P)
    if not session_has_signer_pubshare(session_ctx, pubshare):
        raise ValueError('The signer\'s pubshare must be included in the list of pubshares.')
    a = get_session_interpolating_value(session_ctx, my_id)
    g = 1 if has_even_y(Q) else n - 1
    d = g * gacc * d_ % n
    s = (k_1 + b * k_2 + e * a * d) % n
    psig = bytes_from_int(s)
    R_s1 = point_mul(G, k_1_)
    R_s2 = point_mul(G, k_2_)
    assert R_s1 is not None
    assert R_s2 is not None
    pubnonce = cbytes(R_s1) + cbytes(R_s2)
    # Optional correctness check. The result of signing should pass signature verification.
    assert partial_sig_verify_internal(psig, my_id, pubnonce, pubshare, session_ctx)
    return psig

#todo: should we hash the signer set (or pubshares) too? Otherwise same nonce will be generate even if the signer set changes
def det_nonce_hash(secshare_: bytes, aggothernonce: bytes, tweaked_gpk: bytes, msg: bytes, i: int) -> int:
    buf = b''
    buf += secshare_
    buf += aggothernonce
    buf += tweaked_gpk
    buf += len(msg).to_bytes(8, 'big')
    buf += msg
    buf += i.to_bytes(1, 'big')
    return int_from_bytes(tagged_hash('FROST/deterministic/nonce', buf))

def deterministic_sign(secshare: bytes, my_id: bytes, aggothernonce: bytes, ids: List[bytes], pubshares: List[PlainPk], tweaks: List[bytes], is_xonly: List[bool], msg: bytes, rand: Optional[bytes]) -> Tuple[bytes, bytes]:
    if rand is not None:
        secshare_ = bytes_xor(secshare, tagged_hash('FROST/aux', rand))
    else:
        secshare_ = secshare

    tweaked_gpk = get_xonly_pk(group_pubkey_and_tweak(pubshares, ids, tweaks, is_xonly))

    k_1 = det_nonce_hash(secshare_, aggothernonce, tweaked_gpk, msg, 0) % n
    k_2 = det_nonce_hash(secshare_, aggothernonce, tweaked_gpk, msg, 1) % n
    # k_1 == 0 or k_2 == 0 cannot occur except with negligible probability.
    assert k_1 != 0
    assert k_2 != 0

    R_s1 = point_mul(G, k_1)
    R_s2 = point_mul(G, k_2)
    assert R_s1 is not None
    assert R_s2 is not None
    pubnonce = cbytes(R_s1) + cbytes(R_s2)
    secnonce = bytearray(bytes_from_int(k_1) + bytes_from_int(k_2))
    try:
        aggnonce = nonce_agg([pubnonce, aggothernonce], [my_id, AGGREGATOR_ID])
    except Exception:
        raise InvalidContributionError(None, "aggothernonce")
    session_ctx = SessionContext(aggnonce, ids, pubshares, tweaks, is_xonly, msg)
    psig = sign(secnonce, secshare, my_id, session_ctx)
    return (pubnonce, psig)

def partial_sig_verify(psig: bytes, ids: List[bytes], pubnonces: List[bytes], pubshares: List[PlainPk], tweaks: List[bytes], is_xonly: List[bool], msg: bytes, i: int) -> bool:
    if not len(ids) == len(pubnonces) == len(pubshares):
        raise ValueError('The ids, pubnonces and pubshares arrays must have the same length.')
    if len(tweaks) != len(is_xonly):
        raise ValueError('The tweaks and is_xonly arrays must have the same length.')
    aggnonce = nonce_agg(pubnonces, ids)
    session_ctx = SessionContext(aggnonce, ids, pubshares, tweaks, is_xonly, msg)
    return partial_sig_verify_internal(psig, ids[i], pubnonces[i], pubshares[i], session_ctx)

#todo: catch `cpoint`` ValueError and return false
def partial_sig_verify_internal(psig: bytes, my_id: bytes, pubnonce: bytes, pubshare: bytes, session_ctx: SessionContext) -> bool:
    (Q, gacc, _, b, R, e) = get_session_values(session_ctx)
    s = int_from_bytes(psig)
    if s >= n:
        return False
    if not session_has_signer_pubshare(session_ctx, pubshare):
        return False
    R_s1 = cpoint(pubnonce[0:33])
    R_s2 = cpoint(pubnonce[33:66])
    Re_s_ = point_add(R_s1, point_mul(R_s2, b))
    Re_s = Re_s_ if has_even_y(R) else point_negate(Re_s_)
    P = cpoint(pubshare)
    if P is None:
        return False
    a = get_session_interpolating_value(session_ctx, my_id)
    g = 1 if has_even_y(Q) else n - 1
    g_ = g * gacc % n
    return point_mul(G, s) == point_add(Re_s, point_mul(P, e * a * g_ % n))

def partial_sig_agg(psigs: List[bytes], ids: List[bytes], session_ctx: SessionContext) -> bytes:
    assert AGGREGATOR_ID not in ids
    if len(psigs) != len(ids):
        raise ValueError('The psigs and ids arrays must have the same length.')
    (Q, _, tacc, _, R, e) = get_session_values(session_ctx)
    s = 0
    for my_id, psig in zip(ids, psigs):
        s_i = int_from_bytes(psig)
        if s_i >= n:
            raise InvalidContributionError(int_from_bytes(my_id), "psig")
        s = (s + s_i) % n
    g = 1 if has_even_y(Q) else n - 1
    s = (s + e * g * tacc) % n
    return xbytes(R) + bytes_from_int(s)
