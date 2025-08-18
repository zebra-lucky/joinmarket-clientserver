# -*- coding: utf-8 -*-

import asyncio
import os
import time
from hashlib import sha256

from bitcointx.core.key import XOnlyPubKey

import jmbitcoin as btc
from jmbase import hextobin, get_log
from jmbitcoin import CCoinKey
from jmclient.configure import jm_single
from jmfrost.chilldkg_ref.chilldkg import (
    params_id,
    hostpubkey_gen,
    participant_step1,
    participant_step2,
    participant_finalize,
    participant_investigate,
    coordinator_step1,
    coordinator_finalize,
    coordinator_investigate,
    SessionParams,
    DKGOutput,
    RecoveryData,
    FaultyParticipantOrCoordinatorError,
    UnknownFaultyParticipantOrCoordinatorError,
    ParticipantMsg1,
    ParticipantMsg2,
    CoordinatorMsg1,
    CoordinatorMsg2,
)
from jmfrost.chilldkg_ref import encpedpop
from jmfrost.chilldkg_ref import simplpedpop
from jmfrost.chilldkg_ref import vss
from jmfrost.secp256k1lab import secp256k1
from jmfrost.frost_ref import reference as frost
from jmfrost.secp256k1lab.bip340 import schnorr_verify


jlog = get_log()


def calc_tweak(pubshares, ids, h=b''):
    pubkey = frost.derive_group_pubkey(pubshares, ids)
    return frost.tagged_hash("TapTweak", pubkey[1:] + h)


def chilldkg_hexlify(data):
    if isinstance(data, bytes):
        return data.hex()
    if isinstance(data, dict):
        return {k: chilldkg_hexlify(v) for k, v in data.items()}
    if hasattr(data, "_asdict"):  # NamedTuple
        return chilldkg_hexlify(data._asdict())
    if isinstance(data, list):
        return [chilldkg_hexlify(v) for v in data]
    return data


def decrypt_ext_recovery(privkey, enc_ext_recovery_base64):
    return btc.ecies_decrypt(privkey, enc_ext_recovery_base64)


def serialize_ext_recovery(mixdepth, address_type, index):
    try:
        res = b''
        res += mixdepth.to_bytes(1, 'big')
        res += address_type.to_bytes(1, 'big')
        res += index.to_bytes(4, 'big')
        return res
    except Exception as e:
        jlog.error(f'serialize_ext_recovery: serialization '
                   f'failed {repr(e)}')


def deserialize_ext_recovery(ext_recovery_bytes):
    try:
        b = ext_recovery_bytes
        i = 0
        mixdepth = int.from_bytes(b[i:i+1], 'big')
        i += 1
        address_type = int.from_bytes(b[i:i+1], 'big')
        i += 1
        index = int.from_bytes(b[i:i+4], 'big')
        i += 4
        assert b[i:] == b''
        return mixdepth, address_type, index
    except Exception as e:
        jlog.error(f'deserialize_ext_recovery: deserialization '
                   f'failed {repr(e)}')


class DKGCoordinator:

    def __init__(self, *, mixdepth, address_type, index,
                 session_id, hostpubkey):
        self.mixdepth = mixdepth
        self.address_type = address_type
        self.index = index
        self.session_id = session_id
        self.hostpubkey = hostpubkey
        self.parties = dict()
        self.sessions = dict()
        self.state = None
        self.cmsg2 = None
        self.ext_recovery = None


class DKGSession:

    def __init__(self, *, session_id, hostpubkey,
                 coord_nick, coord_hostpubkey):
        self.session_id = session_id
        self.hostpubkey = hostpubkey
        self.coord_nick = coord_nick
        self.coord_hostpubkey = coord_hostpubkey
        self.dkg_init_sec = 0
        self.state1 = None
        self.state2 = None
        self.dkg_output = None
        self.recovery_data = None


COORDINATOR = 'coordinator'


class DKGClient:

    DKG_WAIT_SEC = 60

    def __init__(self, wallet_service):
        self.aborted = False
        self.testflag = False
        self.offerlist = []
        self.jm_up_loop = None
        self.jm_up = False
        self.dkg_gen_list = []
        self.current_dkg_gen = None

        self.wallet_service = wallet_service
        hostpubkeys = jm_single().config.get('FROST', 'hostpubkeys')
        self.hostpubkeys = [hextobin(p) for p in hostpubkeys.split(',')]
        self.t = jm_single().config.getint('FROST', 't')
        self.session_params = SessionParams(self.hostpubkeys, self.t)
        self.dkg_coordinators = dict()
        self.dkg_sessions = dict()

    def on_jm_up(self):
        self.jm_up = True

    def find_pubkey_by_pubkeyhash(self, pubkeyhash):
        for pubkey in self.hostpubkeys:
            if pubkeyhash == sha256(pubkey).hexdigest():
                return pubkey

    async def dkg_gen(self):
        if self.dkg_gen_list:
            self.current_dkg_gen = self.dkg_gen_list[0]
        else:
            self.current_dkg_gen = None
        return self.current_dkg_gen

    def dkg_init(self, mixdepth, address_type, index):
        try:
            wallet = self.wallet_service.wallet
            hostseckey = wallet._hostseckey[:32]
            hostpubkey = hostpubkey_gen(hostseckey)
            hostpubkeyhash = sha256(hostpubkey).digest()
            session_id = sha256(os.urandom(32)).digest()
            coordinator = DKGCoordinator(mixdepth=mixdepth,
                                         address_type=address_type,
                                         index=index,
                                         session_id=session_id,
                                         hostpubkey=hostpubkey)
            md_type_idx = (coordinator.mixdepth,
                           coordinator.address_type,
                           coordinator.index)
            ext_recovery_bytes = serialize_ext_recovery(*md_type_idx)
            coordinator.ext_recovery = self.encrypt_ext_recovery(
                coordinator, ext_recovery_bytes)
            self.dkg_coordinators[session_id] = coordinator
            session = DKGSession(session_id=session_id,
                                 hostpubkey=hostpubkey,
                                 coord_nick=COORDINATOR,
                                 coord_hostpubkey=hostpubkey)
            self.dkg_sessions[session_id] = session
            coordinator.parties[hostpubkey] = COORDINATOR
            coordinator.sessions[hostpubkey] = {}
            pmsg1 = self.party_step1(session_id, serialize=False)
            if not pmsg1:
                raise Exception(f'Can not create pmsg1 for '
                                f'session {session_id.hex()}')
            coordinator.sessions[hostpubkey]['nick'] = COORDINATOR
            coordinator.sessions[hostpubkey]['pmsg1'] = pmsg1
            coin_key = CCoinKey.from_secret_bytes(hostseckey)
            sig = coin_key.sign_schnorr_no_tweak(session_id)
            return hostpubkeyhash.hex(), session_id, sig.hex()
        except Exception as e:
            jlog.error(f'dkg_init: {repr(e)}')
        return None, None, None

    def on_dkg_init(self, nick, pubkeyhash, session_id, sig):
        try:
            if session_id in self.dkg_sessions:
                raise Exception(f'session {session_id.hex()} already exists')
            pubkey = self.find_pubkey_by_pubkeyhash(pubkeyhash)
            if not pubkey:
                raise Exception(f'pubkey for {pubkeyhash.hex()} not found')
            xpubkey = XOnlyPubKey(pubkey[1:])
            if not xpubkey.verify_schnorr(session_id, hextobin(sig)):
                raise Exception('signature verification failed')
            wallet = self.wallet_service.wallet
            hostseckey = wallet._hostseckey[:32]
            hostpubkey = hostpubkey_gen(hostseckey)
            hostpubkeyhash = sha256(hostpubkey).digest()
            session = DKGSession(session_id=session_id,
                                 hostpubkey=hostpubkey,
                                 coord_nick=nick,
                                 coord_hostpubkey=pubkey)
            self.dkg_sessions[session_id] = session
            coin_key = CCoinKey.from_secret_bytes(hostseckey)
            sig = coin_key.sign_schnorr_no_tweak(session_id)
            pmsg1 = self.party_step1(session_id)
            return (nick, hostpubkeyhash.hex(), session_id.hex(),
                    sig.hex(), pmsg1)
        except Exception as e:
            jlog.error(f'on_dkg_init: {repr(e)}')
        return None, None, None, None, None

    def party_step1(self, session_id, *, serialize=True):
        try:
            session = self.dkg_sessions.get(session_id)
            if not session:
                raise Exception(f'session {session_id.hex()} not found')
            if session.state1:
                raise Exception(f'session.state1 already set '
                                f'for {session_id.hex()}')
            wallet = self.wallet_service.wallet
            hostseckey = wallet._hostseckey[:32]
            random = os.urandom(32)
            session.state1, pmsg1 = participant_step1(
                hostseckey, self.session_params, random)
            if serialize:
                pmsg1 = self.serialize_pmsg1(pmsg1)
            jlog.debug('party_step1 run')
            return pmsg1
        except Exception as e:
            jlog.error(f'party_step1: {repr(e)}')

    def on_dkg_pmsg1(self, nick, pubkeyhash, session_id, sig, pmsg1):
        try:
            coordinator = self.dkg_coordinators.get(session_id)
            if not coordinator:
                raise Exception(f'session {session_id.hex()} not found')
            pubkey = self.find_pubkey_by_pubkeyhash(pubkeyhash)
            if not pubkey:
                raise Exception(f'pubkey for {pubkeyhash.hex()} not found')
            xpubkey = XOnlyPubKey(pubkey[1:])
            if not xpubkey.verify_schnorr(session_id, hextobin(sig)):
                raise Exception(f'signature verification failed')
            if pubkey in coordinator.parties:
                jlog.debug(f'pubkey {pubkey.hex()} already in'
                           f' coordinator parties')
                return None, None
            coordinator.parties[pubkey] = nick

            if not pubkey in coordinator.sessions:
                coordinator.sessions[pubkey] = {}
            coordinator.sessions[pubkey]['nick'] = nick
            coordinator.sessions[pubkey]['pmsg1'] = pmsg1

            ready_list = set()
            if len(coordinator.sessions) == len(self.hostpubkeys):
                for session in coordinator.sessions.values():
                    if session['nick'] == COORDINATOR:
                        continue
                    ready_list.add(session['nick'])
            if ready_list and len(ready_list) == len(self.hostpubkeys) - 1:
                cmsg1 = self.coordinator_step1(session_id)
                pmsg2 = self.party_step2(session_id, cmsg1, serialize=False)
                self.on_dkg_pmsg2(COORDINATOR, session_id, pmsg2)
                return ready_list, self.serialize_cmsg1(cmsg1)
            else:
                return None, None
        except Exception as e:
            jlog.error(f'on_dkg_pmsg1: {repr(e)}')
        return None, None

    def coordinator_step1(self, session_id):
        try:
            coordinator = self.dkg_coordinators.get(session_id)
            if not coordinator:
                raise Exception(f'session {session_id.hex()} not found')
            if coordinator.state:
                raise Exception(f'coordinator.state already set '
                                f'for {session_id.hex()}')
            pmsgs1 = []
            for pubkey in self.hostpubkeys:
                session = coordinator.sessions[pubkey]
                pmsgs1.append(session['pmsg1'])

            coordinator.state, cmsg1 = coordinator_step1(
                pmsgs1, self.session_params)
            jlog.debug('coordinator_step1 run')
            return cmsg1
        except Exception as e:
            jlog.error(f'coordinator_step1: {repr(e)}')

    def party_step2(self, session_id, cmsg1, *, serialize=True):
        try:
            session = self.dkg_sessions.get(session_id)
            if not session:
                raise Exception(f'session {session_id.hex()} not found')
            if session.state2:
                raise Exception(f'session.state2 already set '
                                f'for {session_id.hex()}')
            wallet = self.wallet_service.wallet
            hostseckey = wallet._hostseckey[:32]
            session.state2, pmsg2 = participant_step2(
                hostseckey, session.state1, cmsg1)
            if serialize:
                pmsg2 = self.serialize_pmsg2(pmsg2)
            jlog.debug('party_step2 run')
            return pmsg2
        except Exception as e:
            jlog.error(f'party_step2: {repr(e)}')

    def on_dkg_pmsg2(self, nick, session_id, pmsg2):
        try:
            coordinator = self.dkg_coordinators.get(session_id)
            if not coordinator:
                raise Exception(f'session {session_id.hex()} not found')
            party = None
            for pubkey in self.hostpubkeys:
                if nick == coordinator.parties.get(pubkey):
                    party = nick
                    break
            if not party:
                raise Exception(f'unknown party {nick}')
            if not pubkey in coordinator.sessions:
                raise Exception(f'party pubkey for {nick} not found')
            if 'pmsg2' in coordinator.sessions[pubkey]:
                raise Exception(f'pmsg2 already set in coordinator sessions '
                                f'for pubkey {pubkey.hex()}')
            coordinator.sessions[pubkey]['pmsg2'] = pmsg2

            ready_list = set()
            if len(coordinator.sessions) == len(self.hostpubkeys):
                for session in coordinator.sessions.values():
                    if session['nick'] == COORDINATOR:
                        continue
                    if not 'pmsg2' in session:
                        continue
                    ready_list.add(session['nick'])
            if ready_list and len(ready_list) == len(self.hostpubkeys) - 1:
                cmsg2 = self.coordinator_step2(session_id)
                ext_recovery = coordinator.ext_recovery
                return ready_list, self.serialize_cmsg2(cmsg2), ext_recovery
            else:
                return None, None, None
        except Exception as e:
            jlog.error(f'on_dkg_pmsg2: {repr(e)}')
        return None, None, None

    def coordinator_step2(self, session_id):
        try:
            coordinator = self.dkg_coordinators.get(session_id)
            if not coordinator:
                raise Exception(f'session {session_id.hex()} not found')
            if coordinator.cmsg2:
                raise Exception(f'coordinator.cmsg2 already set '
                                f'for {session_id.hex()}')
            pmsgs2 = []
            for pubkey in self.hostpubkeys:
                session = coordinator.sessions[pubkey]
                pmsgs2.append(session['pmsg2'])
            cmsg2, dkg_output, recovery_data = coordinator_finalize(
                coordinator.state, pmsgs2)
            coordinator.cmsg2 = cmsg2
            jlog.debug('coordinator_step2 run')
            return cmsg2
        except Exception as e:
            jlog.error(f'coordinator_step2 : {repr(e)}')

    def finalize(self, session_id, cmsg2, ext_recovery):
        try:
            session = self.dkg_sessions.get(session_id)
            if not session:
                raise Exception(f'session {session_id.hex()} not found')
            if session.dkg_output:
                raise Exception(f'session.dkg_output already set '
                                f'for {session_id.hex()}')
            session.dkg_output, session.recovery_data = participant_finalize(
                session.state2, cmsg2)
            jlog.debug('finalize run')
            dkg_man = self.wallet_service.dkg
            session_id = session.session_id
            coordinator = self.dkg_coordinators.get(session_id)
            coord_hostpubkey = session.coord_hostpubkey
            if coordinator:
                dkg_man.add_coordinator_data(
                    session_id=session_id,
                    dkg_output=session.dkg_output,
                    hostpubkeys=self.hostpubkeys,
                    t=self.t,
                    recovery_data=session.recovery_data,
                    ext_recovery=ext_recovery)
            else:
                dkg_man.add_party_data(
                    session_id=session_id,
                    dkg_output=session.dkg_output,
                    hostpubkeys=self.hostpubkeys,
                    t=self.t,
                    recovery_data=session.recovery_data,
                    ext_recovery=ext_recovery)
                self.dkg_sessions.pop(session_id)
            return True
        except Exception as e:
            jlog.error(f'finalize: {repr(e)}')
            return False

    def on_dkg_finalized(self, nick, session_id):
        try:
            coordinator = self.dkg_coordinators.get(session_id)
            if not coordinator:
                raise Exception(f'session {session_id.hex()} not found')
            party = None
            for pubkey in self.hostpubkeys:
                if nick == coordinator.parties.get(pubkey):
                    party = nick
                    break
            if not party:
                raise Exception(f'unknown party {nick}')
            if not pubkey in coordinator.sessions:
                raise Exception(f'party pubkey for {nick} not found')
            if 'finalized' in coordinator.sessions[pubkey]:
                raise Exception(f'finalized already set in coordinator '
                                f'sessions for pubkey {pubkey.hex()}')
            coordinator.sessions[pubkey]['finalized'] = True

            ready_list = set()
            if len(coordinator.sessions) == len(self.hostpubkeys):
                for session in coordinator.sessions.values():
                    if session['nick'] == COORDINATOR:
                        continue
                    if not 'finalized' in session:
                        continue
                    ready_list.add(session['nick'])
            if ready_list and len(ready_list) == len(self.hostpubkeys) - 1:
                ext_recovery = coordinator.ext_recovery
                self.finalize(session_id, coordinator.cmsg2, ext_recovery)
                return True
            return False
        except Exception as e:
            jlog.error(f'on_dkg_finalized: {repr(e)}')
            return False

    async def wait_on_dkg_output(self, session_id):
        try:
            session = self.dkg_sessions.get(session_id)
            if not session:
                raise Exception(f'session {session_id.hex()} not found')
            while True:
                await asyncio.sleep(1)
                if session.dkg_output:
                    break
                waiting_sec = time.time() - session.dkg_init_sec
                if waiting_sec > self.DKG_WAIT_SEC:
                    raise Exception(f'timed out DKG session '
                                    f'{session_id.hex()}')
            return session.dkg_output.threshold_pubkey
        except Exception as e:
            jlog.warn(f'wait_on_dkg_output: {repr(e)}')
        finally:
            sess_id = self.dkg_sessions.pop(session_id, None)
            if not sess_id:
                jlog.debug(f'wait_on_dkg_output: session {session_id.hex()}'
                           f' not found in the dkg_sessions')
            sess_id = self.dkg_coordinators.pop(session_id, None)
            if not sess_id:
                jlog.debug(f'wait_on_dkg_output: session {session_id.hex()}'
                           f' not found in the dkg_coordinators')

    def encrypt_ext_recovery(self, coordinator, ext_recovery_bytes):
        try:
            pubkey = coordinator.hostpubkey
            return btc.ecies_encrypt(ext_recovery_bytes, pubkey)
        except Exception as e:
            jlog.error(f'enc_ext_recovery: {repr(e)}')

    def serialize_pmsg1(self, pmsg1):
        try:
            enc_pmsg = pmsg1.enc_pmsg
            simpl_pmsg = enc_pmsg.simpl_pmsg
            com = simpl_pmsg.com
            pop = simpl_pmsg.pop
            ges = com.ges
            pubnonce = enc_pmsg.pubnonce
            enc_shares = enc_pmsg.enc_shares

            res = b''
            res += len(ges).to_bytes(2, 'big')
            for ge in ges:
                res += ge.to_bytes_compressed()
            res += bytes(pop)
            res += pubnonce
            res += len(enc_shares).to_bytes(2, 'big')
            for es in enc_shares:
                res += es.to_bytes()
            return res
        except Exception as e:
            jlog.error(f'serialize_pmsg1: serialization failed {repr(e)}')

    def deserialize_pmsg1(self, pmsg1_bytes):
        try:
            b = pmsg1_bytes
            i = 0

            ges_len = int.from_bytes(b[i:i+2], 'big')
            i += 2

            ges = []
            for j in range(ges_len):
                ge = secp256k1.GE.from_bytes_compressed(b[i:i+33])
                ges.append(ge)
                i += 33

            pop = simplpedpop.Pop(b[i:i+64])
            i += 64

            pubnonce = b[i:i+33]
            i += 33

            enc_shares_len = int.from_bytes(b[i:i+2], 'big')
            i += 2

            enc_shares = []
            for j in range(enc_shares_len):
                es = secp256k1.Scalar.from_bytes_checked(b[i:i+32])
                enc_shares.append(es)
                i += 32

            assert b[i:] == b''

            com = vss.VSSCommitment(ges)
            simpl_pmsg = simplpedpop.ParticipantMsg(com, pop)
            enc_pmsg = encpedpop.ParticipantMsg(simpl_pmsg, pubnonce,
                                                enc_shares)
            return ParticipantMsg1(enc_pmsg)
        except Exception as e:
            jlog.error(f'deserialize_pmsg1: deserialization failed {repr(e)}')

    def serialize_pmsg2(self, pmsg2):
        try:
            return b'' + pmsg2.sig
        except Exception as e:
            jlog.error(f'serialize_pmsg2: serialization failed {repr(e)}')

    def deserialize_pmsg2(self, pmsg2_bytes):
        try:
            return ParticipantMsg2(pmsg2_bytes)
        except Exception as e:
            jlog.error(f'deserialize_pmsg2: deserialization failed {repr(e)}')

    def serialize_cmsg1(self, cmsg1):
        try:
            enc_cmsg = cmsg1.enc_cmsg
            simpl_cmsg = enc_cmsg.simpl_cmsg
            coms_to_secrets = simpl_cmsg.coms_to_secrets
            sum_coms_to_nonconst_terms = simpl_cmsg.sum_coms_to_nonconst_terms
            pops = simpl_cmsg.pops
            pubnonces = enc_cmsg.pubnonces
            enc_secshares = cmsg1.enc_secshares

            res = b''
            res += len(coms_to_secrets).to_bytes(2, 'big')
            for cts in coms_to_secrets:
                res += cts.to_bytes_compressed()
            res += len(sum_coms_to_nonconst_terms).to_bytes(2, 'big')
            for sctnct in sum_coms_to_nonconst_terms:
                res += sctnct.to_bytes_compressed()
            res += len(pops).to_bytes(2, 'big')
            for pop in pops:
                res += bytes(pop)
            res += len(pubnonces).to_bytes(2, 'big')
            for pubnonce in pubnonces:
                res += pubnonce
            res += len(enc_secshares).to_bytes(2, 'big')
            for es in enc_secshares:
                res += es.to_bytes()
            return res
        except Exception as e:
            jlog.error(f'serialize_cmsg1: serialization failed {repr(e)}')

    def deserialize_cmsg1(self, cmsg1_bytes):
        try:
            b = cmsg1_bytes
            i = 0

            coms_to_secrets_len = int.from_bytes(b[i:i+2], 'big')
            i += 2
            coms_to_secrets = []
            for j in range(coms_to_secrets_len):
                cts = secp256k1.GE.from_bytes_compressed(b[i:i+33])
                coms_to_secrets.append(cts)
                i += 33

            sum_coms_to_nonconst_terms_len = int.from_bytes(b[i:i+2], 'big')
            i += 2
            sum_coms_to_nonconst_terms = []
            for j in range(sum_coms_to_nonconst_terms_len):
                sctnct = secp256k1.GE.from_bytes_compressed(b[i:i+33])
                sum_coms_to_nonconst_terms.append(sctnct)
                i += 33

            pops_len = int.from_bytes(b[i:i+2], 'big')
            i += 2
            pops = []
            for j in range(pops_len):
                pop = simplpedpop.Pop(b[i:i+64])
                pops.append(pop)
                i += 64

            pubnonces_len = int.from_bytes(b[i:i+2], 'big')
            i += 2
            pubnonces = []
            for j in range(pubnonces_len):
                pubnonce = b[i:i+33]
                pubnonces.append(pubnonce)
                i += 33

            enc_secshares_len = int.from_bytes(b[i:i+2], 'big')
            i += 2
            enc_secshares = []
            for j in range(enc_secshares_len):
                es = secp256k1.Scalar.from_bytes_checked(b[i:i+32])
                enc_secshares.append(es)
                i += 32

            assert b[i:] == b''

            simpl_cmsg = simplpedpop.CoordinatorMsg(
                    coms_to_secrets, sum_coms_to_nonconst_terms, pops)
            enc_cmsg = encpedpop.CoordinatorMsg(simpl_cmsg, pubnonces)
            return CoordinatorMsg1(enc_cmsg, enc_secshares)
        except Exception as e:
            jlog.error(f'deserialize_cmsg1: deserialization failed {repr(e)}')

    def serialize_cmsg2(self, cmsg2):
        try:
            return b'' + cmsg2.cert
        except Exception as e:
            jlog.error(f'serialize_cmsg2: serialization failed {repr(e)}')

    def deserialize_cmsg2(self, cmsg2_bytes):
        try:
            return CoordinatorMsg2(cmsg2_bytes)
        except Exception as e:
            jlog.error(f'deserialize_cmsg2: deserialization failed {repr(e)}')


class FROSTCoordinator:

    def __init__(self, *, session_id, hostpubkey, dkg_session_id, msg):
        self.session_id = session_id
        self.frost_init_sec = 0
        self.hostpubkey = hostpubkey
        self.dkg_session_id = dkg_session_id
        self.msg = msg
        self.parties = dict()
        self.sessions = dict()
        self.nonce_agg = None
        self.ids = []
        self.sig = None
        self.tweaked_pubkey = None

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return (f'FROSTCoordinator(session_id={self.session_id}, '
                f'frost_init_sec={self.frost_init_sec}, '
                f'hostpubkey={self.hostpubkey}, '
                f'dkg_session_id={self.dkg_session_id}, '
                f'msg={self.msg}, '
                f'parties={self.parties}, '
                f'sessions={self.sessions}, '
                f'nonce_agg={self.nonce_agg}, '
                f'ids={self.ids}, '
                f'sig={self.sig})')


class FROSTSession:

    def __init__(self, *, session_id, hostpubkey,
                 coord_nick, coord_hostpubkey):
        self.session_id = session_id
        self.hostpubkey = hostpubkey
        self.coord_nick = coord_nick
        self.coord_hostpubkey = coord_hostpubkey
        self.sec_nonce = None
        self.pub_nonce = None
        self.partial_sig = None

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return (f'FROSTSession(session_id={self.session_id}, '
                f'hostpubkey={self.hostpubkey}, '
                f'coord_nick={self.coord_nick}, '
                f'coord_hostpubkey={self.coord_hostpubkey}, '
                f'sec_nonce={self.sec_nonce}, '
                f'pub_nonce={self.pub_nonce}, '
                f'partial_sig={self.partial_sig})')


class FROSTClient(DKGClient):

    FROST_WAIT_SEC = 60

    def __init__(self, wallet_service):
        super().__init__(wallet_service)
        self.frost_coordinators = dict()
        self.frost_sessions = dict()

    def frost_init(self, dkg_session_id, msg_bytes):
        try:
            wallet = self.wallet_service.wallet
            hostseckey = wallet._hostseckey[:32]
            hostpubkey = hostpubkey_gen(hostseckey)
            self.my_id = None
            for i, p in enumerate(self.hostpubkeys):
                if p == hostpubkey:
                    self.my_id = i
                    break
            assert self.my_id is not None, (f'unknown hostpubkey '
                                            f'{hostpubkey.hex()}')
            hostpubkeyhash = sha256(hostpubkey).digest()
            session_id = sha256(os.urandom(32)).digest()
            coordinator = FROSTCoordinator(session_id=session_id,
                                           hostpubkey=hostpubkey,
                                           dkg_session_id=dkg_session_id,
                                           msg=msg_bytes)
            self.frost_coordinators[session_id] = coordinator
            session = FROSTSession(session_id=session_id,
                                   hostpubkey=hostpubkey,
                                   coord_nick=COORDINATOR,
                                   coord_hostpubkey=hostpubkey)
            self.frost_sessions[session_id] = session
            coordinator.parties[hostpubkey] = COORDINATOR
            coordinator.sessions[hostpubkey] = {}
            coordinator.sessions[hostpubkey]['nick'] = COORDINATOR
            pub_nonce = self.frost_round1(session_id)
            if not pub_nonce:
                raise Exception(f'Can not create pub_nonce for '
                                f'session {session_id.hex()}')
            coordinator.sessions[hostpubkey]['pub_nonce'] = pub_nonce
            coin_key = CCoinKey.from_secret_bytes(hostseckey)
            sig = coin_key.sign_schnorr_no_tweak(session_id)
            return hostpubkeyhash.hex(), session_id, sig.hex()
        except Exception as e:
            jlog.error(f'frost_init: {repr(e)}')
        return None, None, None

    def on_frost_init(self, nick, pubkeyhash, session_id, sig):
        try:
            if session_id in self.frost_sessions:
                raise Exception(f'session {session_id.hex()} already exists')
            pubkey = self.find_pubkey_by_pubkeyhash(pubkeyhash)
            if not pubkey:
                raise Exception(f'pubkey for {pubkeyhash.hex()} not found')
            xpubkey = XOnlyPubKey(pubkey[1:])
            if not xpubkey.verify_schnorr(session_id, hextobin(sig)):
                raise Exception('signature verification failed')
            wallet = self.wallet_service.wallet
            hostseckey = wallet._hostseckey[:32]
            hostpubkey = hostpubkey_gen(hostseckey)
            self.my_id = None
            for i, p in enumerate(self.hostpubkeys):
                if p == hostpubkey:
                    self.my_id = i
                    break
            assert self.my_id is not None
            hostpubkeyhash = sha256(hostpubkey).digest()
            session = FROSTSession(session_id=session_id,
                                   hostpubkey=hostpubkey,
                                   coord_nick=nick,
                                   coord_hostpubkey=pubkey)
            self.frost_sessions[session_id] = session
            coin_key = CCoinKey.from_secret_bytes(hostseckey)
            sig = coin_key.sign_schnorr_no_tweak(session_id)
            pub_nonce = self.frost_round1(session_id)
            return (nick, hostpubkeyhash.hex(), session_id.hex(),
                    sig.hex(), pub_nonce)
        except Exception as e:
            jlog.error(f'on_frost_init: {repr(e)}')
        return None, None, None, None, None

    def frost_round1(self, session_id):
        try:
            session = self.frost_sessions.get(session_id)
            if not session:
                raise Exception(f'session {session_id.hex()} not found')
            if session.sec_nonce:
                raise Exception(f'session.sec_nonce already set '
                                f'for {session_id.hex()}')
            session.sec_nonce, session.pub_nonce = frost.nonce_gen(
                secshare=None, pubshare=None, group_pk=None, msg=None,
                extra_in=None)
            jlog.debug('frost_round1 run')
            return session.pub_nonce
        except Exception as e:
            jlog.error(f'frost_round1: {repr(e)}')

    def on_frost_round1(self, nick, pubkeyhash, session_id, sig, pub_nonce):
        try:
            coordinator = self.frost_coordinators.get(session_id)
            if not coordinator:
                raise Exception(f'session {session_id.hex()} not found')
            if len(coordinator.sessions) == self.t:
                jlog.debug('on_frost_round1: miminum pub_nonce set already '
                           'presented, ignoring additional pub_nonce')
                return None, None, None, None, None
            pubkey = self.find_pubkey_by_pubkeyhash(pubkeyhash)
            if not pubkey:
                raise Exception(f'pubkey for {pubkeyhash} not found')
            xpubkey = XOnlyPubKey(pubkey[1:])
            if not xpubkey.verify_schnorr(session_id, hextobin(sig)):
                raise Exception(f'signature verification failed')
            if pubkey in coordinator.parties:
                jlog.debug(f'pubkey {pubkey.hex()} already in'
                           f' coordinator parties')
                return None, None, None, None, None
            coordinator.parties[pubkey] = nick

            if not pubkey in coordinator.sessions:
                coordinator.sessions[pubkey] = {}
            coordinator.sessions[pubkey]['nick'] = nick
            coordinator.sessions[pubkey]['pub_nonce'] = pub_nonce

            ready_list = set()
            if len(coordinator.sessions) == self.t:
                for session in coordinator.sessions.values():
                    if session['nick'] == COORDINATOR:
                        continue
                    ready_list.add(session['nick'])
            if ready_list and len(ready_list) == self.t - 1:
                coordinator.nonce_agg, dkg_session_id, ids, msg = \
                    self.frost_agg1(session_id)
                partial_sig = self.frost_round2(
                    session_id, coordinator.nonce_agg,
                    dkg_session_id, ids, msg)
                self.on_frost_round2(
                    COORDINATOR, session_id, partial_sig)
                return (ready_list, coordinator.nonce_agg,
                        dkg_session_id, ids, msg)
            else:
                return None, None, None, None, None
        except Exception as e:
            jlog.error(f'on_frost_round1: {repr(e)}')
        return None, None, None, None, None

    def frost_agg1(self, session_id):
        try:
            coordinator = self.frost_coordinators.get(session_id)
            if not coordinator:
                raise Exception(f'session {session_id.hex()} not found')
            if coordinator.nonce_agg:
                raise Exception(f'coordinator.nonce_agg already set '
                                f'for {session_id.hex()}')
            pub_nonces = []
            ids = []
            for i, pubkey in enumerate(self.hostpubkeys):
                session = coordinator.sessions.get(pubkey)
                if not session:
                    continue
                pub_nonce = session.get('pub_nonce')
                if not pub_nonce:
                    continue
                pub_nonces.append(pub_nonce)
                ids.append(i)
            coordinator.ids = ids.copy()
            assert len(ids) == self.t
            coordinator.nonce_agg = frost.nonce_agg(pub_nonces, ids)
            jlog.debug('frost_agg1 run')
            return (coordinator.nonce_agg, coordinator.dkg_session_id, ids,
                    coordinator.msg)
        except Exception as e:
            jlog.error(f'frost_agg1: {repr(e)}')
        return None, None, None, None

    def frost_round2(self, session_id, nonce_agg, dkg_session_id, ids, msg):
        try:
            session = self.frost_sessions.get(session_id)
            if not session:
                raise Exception(f'session {session_id.hex()} not found')
            if session.partial_sig:
                raise Exception(f'session.partial_sig already set '
                                f'for {session_id.hex()}')
            dkg = self.wallet_service.wallet.dkg
            secshare = dkg._dkg_secshare.get(dkg_session_id)
            if not secshare:
                raise Exception(f'secshare not found for '
                                f'{dkg_session_id.hex()}')
            _pubshares = dkg._dkg_pubshares.get(dkg_session_id)
            pubshares = []
            for i, pubshare in enumerate(_pubshares):
                if i not in ids:
                    continue
                pubshares.append(pubshare)
            tweak = calc_tweak(pubshares, ids)
            tweaks = [tweak]
            is_xonly = [True]
            session_ctx = frost.SessionContext(
                nonce_agg, ids, pubshares, tweaks, is_xonly, msg)
            session.partial_sig = partial_sig = frost.sign(
                session.sec_nonce, secshare, self.my_id, session_ctx)
            jlog.debug('frost_round2 run')
            return partial_sig
        except Exception as e:
            jlog.error(f'frost_round2: {repr(e)}')

    def on_frost_round2(self, nick, session_id, partial_sig):
        try:
            coordinator = self.frost_coordinators.get(session_id)
            if not coordinator:
                raise Exception(f'session {session_id.hex()} not found')
            party = None
            for pubkey in self.hostpubkeys:
                if nick == coordinator.parties.get(pubkey):
                    party = nick
                    break
            if not party:
                raise Exception(f'unknown party {nick}')
            if not pubkey in coordinator.sessions:
                raise Exception(f'party pubkey for {nick} not found')
            if 'partial_sig' in coordinator.sessions[pubkey]:
                raise Exception(f'partial_sig already set in coordinator '
                                f'sessions for pubkey {pubkey.hex()}')
            coordinator.sessions[pubkey]['partial_sig'] = partial_sig

            ready_list = set()
            if len(coordinator.sessions) == self.t:
                for session in coordinator.sessions.values():
                    if session['nick'] == COORDINATOR:
                        continue
                    if not 'partial_sig' in session:
                        continue
                    ready_list.add(session['nick'])
            if ready_list and len(ready_list) == self.t - 1:
                dkg_session_id = coordinator.dkg_session_id
                dkg = self.wallet_service.wallet.dkg
                _pubshares = dkg._dkg_pubshares.get(dkg_session_id)
                if not _pubshares:
                    raise Exception(f'pubshares not found for '
                                    f'{dkg_session_id.hex()}')
                ids = coordinator.ids
                pubshares = []
                for i, pubshare in enumerate(_pubshares):
                    if i not in ids:
                        continue
                    pubshares.append(pubshare)
                tweak = calc_tweak(pubshares, ids)
                tweaks = [tweak]
                is_xonly = [True]
                session_ctx = frost.SessionContext(
                    coordinator.nonce_agg, ids, pubshares, tweaks,
                    is_xonly, coordinator.msg)
                partial_sigs = []
                for pubkey in self.hostpubkeys:
                    session = coordinator.sessions.get(pubkey)
                    if not session:
                        continue
                    if 'partial_sig' in session:
                        partial_sigs.append(session['partial_sig'])
                sig = frost.partial_sig_agg(
                    partial_sigs, ids, session_ctx)
                tweak_ctx = frost.group_pubkey_and_tweak(
                    pubshares, ids, tweaks, is_xonly)
                Q , _, _ = tweak_ctx
                tweaked_pubkey = frost.xbytes(Q)
                if not schnorr_verify(coordinator.msg, tweaked_pubkey, sig):
                    raise Exception(f'on_frost_round2: schnorr_verify failed '
                                    f'for {dkg_session_id.hex()}')
                coordinator.sig = sig
                coordinator.tweaked_pubkey = frost.cbytes(Q)
                return sig
            else:
                return None
        except Exception as e:
            jlog.error(f'on_frost_round2: {repr(e)}')
        return None

    async def wait_on_sig(self, session_id):
        try:
            coordinator = self.frost_coordinators.get(session_id)
            if not coordinator:
                raise Exception(f'session {session_id.hex()} not found')
            while True:
                await asyncio.sleep(1)
                if coordinator.sig:
                    break
                waiting_sec = time.time() - coordinator.frost_init_sec
                if waiting_sec > self.FROST_WAIT_SEC:
                    raise Exception(f'timed out FROST session '
                                    f'{session_id.hex()}')
            return coordinator.sig, coordinator.tweaked_pubkey
        except Exception as e:
            jlog.error(f'wait_on_sig: {repr(e)}')
            return None, repr(e)
        finally:
            sess_id = self.frost_sessions.pop(session_id, None)
            if not sess_id:
                jlog.debug(f'wait_on_sig: session {session_id.hex()} not found'
                           f' in the frost_sessions')
            sess_id = self.frost_coordinators.pop(session_id, None)
            if not sess_id:
                jlog.debug(f'wait_on_sig: session {session_id.hex()} not found'
                           f' in the frost_coordinators')
