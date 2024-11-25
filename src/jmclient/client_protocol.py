#! /usr/bin/env python

import asyncio
import base64
import time
from twisted.internet import protocol, reactor, task
from twisted.internet.error import (ConnectionLost, ConnectionAborted,
                                    ConnectionClosed, ConnectionDone)
from twisted.protocols import amp
try:
    from twisted.internet.ssl import ClientContextFactory
except ImportError:
    pass
from jmbase import commands, jmprint
import binascii
import json
import hashlib
import os
from jmbase import (get_log, EXIT_FAILURE, hextobin, bintohex,
                    utxo_to_utxostr, bdict_sdict_convert, twisted_sys_exit)
from jmclient.maker import Maker
from jmclient import (jm_single, get_mchannels,
                      RegtestBitcoinCoreInterface,
                      SNICKERReceiver, process_shutdown, FrostWallet)
import jmbitcoin as btc

from .frost_clients import DKGClient

# module level variable representing the port
# on which the daemon is running.
# note that this var is only set if we are running
# client+daemon in one process.
daemon_serving_port = -1
daemon_serving_host = ""

def get_daemon_serving_params():
    return (daemon_serving_host, daemon_serving_port)

jlog = get_log()

class BaseClientProtocol(amp.AMP):
    def checkClientResponse(self, response):
        """A generic check of client acceptance; any failure
        is considered criticial.
        """
        if 'accepted' not in response or not response['accepted']:
            #Unintended client shutdown cannot be tested easily in twisted
            reactor.stop() #pragma: no cover

    def defaultErrback(self, failure):
        #see testing note above
        failure.trap(ConnectionAborted, ConnectionClosed, ConnectionDone,
                     ConnectionLost) #pragma: no cover

    def defaultCallbacks(self, d):
        d.addCallback(self.checkClientResponse)
        d.addErrback(self.defaultErrback)

class JMProtocolError(Exception):
    pass

class BIP78ClientProtocol(BaseClientProtocol):

    def __init__(self, manager, params,
                 success_callback, failure_callback,
                 tls_whitelist=[], mode="sender"):
        self.manager = manager
        # can be "sender" or "receiver"
        self.mode = mode
        self.success_callback = success_callback
        self.failure_callback = failure_callback
        if self.mode == "sender":
            self.params = params
        else:
            # receiver only learns params from request
            self.params = None
        if len(tls_whitelist) == 0:
            if isinstance(jm_single().bc_interface,
                          RegtestBitcoinCoreInterface):
                tls_whitelist = ["127.0.0.1"]
        self.tls_whitelist = tls_whitelist

    def connectionMade(self):
        jcg = jm_single().config.get
        if self.mode == "sender":
            netconfig = {"socks5_host": jcg("PAYJOIN", "onion_socks5_host"),
                         "socks5_port": jcg("PAYJOIN", "onion_socks5_port"),
                         "tls_whitelist": ",".join(self.tls_whitelist),
                         "servers": [self.manager.server]}
            d = self.callRemote(commands.BIP78SenderInit,
                                netconfig=netconfig)
        else:
            netconfig = {"port": 80,
                         "tor_control_host": jcg("PAYJOIN", "tor_control_host"),
                         "tor_control_port": jcg("PAYJOIN", "tor_control_port"),
                         "onion_serving_host": jcg("PAYJOIN", "onion_serving_host"),
                         "onion_serving_port": jcg("PAYJOIN", "onion_serving_port")}
            d = self.callRemote(commands.BIP78ReceiverInit,
                                netconfig=netconfig)
        self.defaultCallbacks(d)

    @commands.BIP78ReceiverUp.responder
    def on_BIP78_RECEIVER_UP(self, hostname):
        self.manager.bip21_uri_from_onion_hostname(hostname)
        return {"accepted": True}

    @commands.BIP78ReceiverOriginalPSBT.responder
    def on_BIP78_RECEIVER_ORIGINAL_PSBT(self, body, params):
        # TODO: we don't need binary key/vals client side, but will have to edit
        # PayjoinConverter for that:
        retval = self.success_callback(body.encode("utf-8"), bdict_sdict_convert(
            params, output_binary=True))
        if not retval[0]:
            d = self.callRemote(commands.BIP78ReceiverSendError, errormsg=retval[1],
                                errorcode=retval[2])
        else:
            d = self.callRemote(commands.BIP78ReceiverSendProposal, psbt=retval[1])
        self.defaultCallbacks(d)
        return {"accepted": True}

    @commands.BIP78ReceiverHiddenServiceShutdown.responder
    def on_BIP78_RECEIVER_HIDDEN_SERVICE_SHUTDOWN(self):
        """ This is called when the daemon has shut down the HS
        because of an invalid message/error. An earlier message
        will have conveyed the reason for the error.
        """
        self.manager.shutdown()
        return {"accepted": True}

    @commands.BIP78ReceiverOnionSetupFailed.responder
    def on_BIP78_RECEIVER_ONION_SETUP_FAILED(self, reason):
        self.manager.info_callback(reason)
        self.manager.shutdown()
        return {"accepted": True}

    @commands.BIP78SenderUp.responder
    def on_BIP78_SENDER_UP(self):
        d = self.callRemote(commands.BIP78SenderOriginalPSBT,
                            body=self.manager.initial_psbt.to_base64(),
                            params=self.params)
        self.defaultCallbacks(d)
        return {"accepted": True}

    @commands.BIP78SenderReceiveProposal.responder
    async def on_BIP78_SENDER_RECEIVE_PROPOSAL(self, psbt):
        if asyncio.iscoroutine(self.success_callback):
            await self.success_callback(psbt, self.manager)
        else:
            self.success_callback(psbt, self.manager)
        return {"accepted": True}

    @commands.BIP78SenderReceiveError.responder
    def on_BIP78_SENDER_RECEIVER_ERROR(self, errormsg, errorcode):
        self.failure_callback(errormsg, errorcode, self.manager)
        return {"accepted": True}

    @commands.BIP78InfoMsg.responder
    def on_BIP78_INFO_MSG(self, infomsg):
        self.manager.info_callback(infomsg)
        return {"accepted": True}

class SNICKERClientProtocol(BaseClientProtocol):

    def __init__(self, client, servers, tls_whitelist=[], oneshot=False):
        # if client is type JMSNICKERReceiver, this will flag
        # the use of the receiver workflow (polling loop).
        # Otherwise it is assumed to be a proposer workloop,
        # which does not have active polling, but only the
        # ability to upload when clients call for it.
        self.client = client
        self.servers = servers
        if len(tls_whitelist) == 0:
            if isinstance(jm_single().bc_interface,
                          RegtestBitcoinCoreInterface):
                tls_whitelist = ["127.0.0.1"]
        self.tls_whitelist = tls_whitelist
        self.processed_proposals = []
        self.oneshot = oneshot

    def connectionMade(self):
        netconfig = {"socks5_host": jm_single().config.get("PAYJOIN", "onion_socks5_host"),
                     "socks5_port": jm_single().config.get("PAYJOIN", "onion_socks5_port"),
                     "servers": self.servers,
                     "tls_whitelist": ",".join(self.tls_whitelist),
                     "filterconfig": "",
                     "credentials": ""}

        if isinstance(self.client, SNICKERReceiver):
            d = self.callRemote(commands.SNICKERReceiverInit,
                                netconfig=netconfig)
        else:
            d = self.callRemote(commands.SNICKERProposerInit,
                                netconfig=netconfig)
            self.defaultCallbacks(d)

    def shutdown(self):
        """ Encapsulates shut down actions.
        """
        if self.proposal_poll_loop:
            self.proposals_poll_loop.stop()

    def poll_for_proposals(self):
        """ May be invoked in a LoopingCall or other
        event loop.
        Retrieves any entries in the proposals_source, then
        compares with existing,
        and invokes parse_proposal on all new entries.
        # TODO considerable thought should go into how to store
        proposals cross-runs, and also handling of keys, which
        must be optional.
        """
        # always check whether the service is still intended to
        # be active, before starting the polling actions:
        if jm_single().config.get("SNICKER", "enabled") != "true":
            self.shutdown()
            return
        d = self.callRemote(commands.SNICKERReceiverGetProposals)
        self.defaultCallbacks(d)

    @commands.SNICKERProposerUp.responder
    def on_SNICKER_PROPOSER_UP(self):
        jlog.info("SNICKER proposer daemon ready.")
        # TODO handle multiple servers correctly
        for s in self.servers:
            if s == "":
                continue
            d = self.callRemote(commands.SNICKERRequestPowTarget,
                                server=s)
            self.defaultCallbacks(d)
        return {"accepted": True}

    @commands.SNICKERReceivePowTarget.responder
    def on_SNICKER_RECEIVE_POW_TARGET(self, server, targetbits):
        proposals = self.client.get_proposals(targetbits)
        d = self.callRemote(commands.SNICKERProposerPostProposals,
            proposals="\n".join([x.decode("utf-8") for x in proposals]),
            server = server)
        self.defaultCallbacks(d)
        return {"accepted": True}

    @commands.SNICKERServerError.responder
    def on_SNICKER_SERVER_ERROR(self, server, errorcode):
        self.client.info_callback("Server: " + str(
        server) + " returned error code: " + str(errorcode))
        return {"accepted": True}

    @commands.SNICKERReceiverUp.responder
    def on_SNICKER_RECEIVER_UP(self):
        if self.oneshot:
            jlog.info("Starting single query to SNICKER server(s).")
            reactor.callLater(0.0, self.poll_for_proposals)
        else:
            jlog.info("Starting SNICKER polling loop")
            self.proposal_poll_loop = task.LoopingCall(
                self.poll_for_proposals)
            poll_interval = int(60.0 * float(
                jm_single().config.get("SNICKER", "polling_interval_minutes")))
            self.proposal_poll_loop.start(poll_interval, now=False)
        return {"accepted": True}

    @commands.SNICKERReceiverProposals.responder
    def on_SNICKER_RECEIVER_PROPOSALS(self, proposals, server):
        """ Just passes through the proposals retrieved from
        any server, to the SNICKERReceiver client object, asynchronously.
        The proposals data must be newline separated.
        """
        try:
            proposals = proposals.split("\n")
        except:
            jlog.warn("Error in parsing proposals from server: " + str(server))
            return {"accepted": True}
        reactor.callLater(0.0, self.process_proposals, proposals)
        return {"accepted": True}

    async def process_proposals(self, proposals):
        await self.client.process_proposals(proposals)
        if self.oneshot:
            process_shutdown()

    @commands.SNICKERProposalsServerResponse.responder
    def on_SNICKER_PROPOSALS_SERVER_RESPONSE(self, response, server):
        self.client.info_callback("Response from server: " + str(server) +\
                                  " was: " + str(response))
        self.client.end_requests_callback(None)
        return {"accepted": True}

class JMClientProtocol(BaseClientProtocol):
    def __init__(self, factory, client, nick_priv=None):
            self.client = client
            self.factory = factory
            if not nick_priv:
                self.nick_priv = hashlib.sha256(
                    os.urandom(16)).digest() + b"\x01"
            else:
                self.nick_priv = nick_priv

            self.shutdown_requested = False

    def connectionMade(self):
        jlog.debug('connection was made, starting client.')
        self.factory.setClient(self)
        self.clientStart()

    def set_nick(self):
        """ Algorithm: take pubkey and hex-serialized it;
        then SHA2(hexpub) but truncate output to nick_hashlen.
        Then encode to a base58 string (no check).
        Then prepend J and version char (e.g. '5').
        Finally append padding to nick_maxencoded (+2).
        """
        self.nick_pubkey = btc.privkey_to_pubkey(self.nick_priv)
        # note we use binascii hexlify directly here because input
        # to hashing must be encoded.
        self.nick_pkh_raw = hashlib.sha256(binascii.hexlify(
            self.nick_pubkey)).digest()[:self.nick_hashlen]
        self.nick_pkh = btc.base58.encode(self.nick_pkh_raw)
        #right pad to maximum possible; b58 is not fixed length.
        #Use 'O' as one of the 4 not included chars in base58.
        self.nick_pkh += 'O' * (self.nick_maxencoded - len(self.nick_pkh))
        #The constructed length will be 1 + 1 + NICK_MAX_ENCODED
        self.nick = self.nick_header + str(self.jm_version) + self.nick_pkh
        jm_single().nickname = self.nick
        informuser = getattr(self.client, "inform_user_details", None)
        if callable(informuser):
            informuser()

    @commands.JMInitProto.responder
    def on_JM_INIT_PROTO(self, nick_hash_length, nick_max_encoded,
                         joinmarket_nick_header, joinmarket_version):
        """Daemon indicates init-ed status and passes back protocol constants.
        Use protocol settings to set actual nick from nick private key,
        then call setup to instantiate message channel connections in the daemon.
        """
        self.nick_hashlen = nick_hash_length
        self.nick_maxencoded = nick_max_encoded
        self.nick_header = joinmarket_nick_header
        self.jm_version = joinmarket_version
        self.set_nick()
        d = self.callRemote(commands.JMStartMC,
                            nick=self.nick)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMRequestMsgSig.responder
    def on_JM_REQUEST_MSGSIG(self, nick, cmd, msg, msg_to_be_signed, hostid):
        sig = btc.ecdsa_sign(str(msg_to_be_signed), self.nick_priv)
        msg_to_return = str(msg) + " " + bintohex(self.nick_pubkey) + " " + sig
        d = self.callRemote(commands.JMMsgSignature,
                            nick=nick,
                            cmd=cmd,
                            msg_to_return=msg_to_return,
                            hostid=hostid)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMRequestMsgSigVerify.responder
    def on_JM_REQUEST_MSGSIG_VERIFY(self, msg, fullmsg, sig, pubkey, nick,
                                    hashlen, max_encoded, hostid):
        pubkey_bin = hextobin(pubkey)
        verif_result = True
        if not btc.ecdsa_verify(str(msg), sig, pubkey_bin):
            # workaround for hostid, which sometimes is lowercase-only for some IRC connections
            if not btc.ecdsa_verify(str(msg[:-len(hostid)] + hostid.lower()), sig, pubkey_bin):
                jlog.debug("nick signature verification failed, ignoring: " + str(nick))
                verif_result = False
        #check that nick matches hash of pubkey
        nick_pkh_raw = hashlib.sha256(pubkey.encode("ascii")).digest()[:hashlen]
        nick_stripped = nick[2:2 + max_encoded]
        #strip right padding
        nick_unpadded = ''.join([x for x in nick_stripped if x != 'O'])
        if not nick_unpadded == btc.base58.encode(nick_pkh_raw):
            jlog.debug("Nick hash check failed, expected: " + str(nick_unpadded)
                       + ", got: " + str(btc.base58.encode(nick_pkh_raw)))
            verif_result = False
        d = self.callRemote(commands.JMMsgSignatureVerify,
                            verif_result=verif_result,
                            nick=nick,
                            fullmsg=fullmsg,
                            hostid=hostid)
        self.defaultCallbacks(d)
        return {'accepted': True}

    def make_tx(self, nick_list, tx):
        d = self.callRemote(commands.JMMakeTx,
                            nick_list=nick_list,
                            tx=tx)
        self.defaultCallbacks(d)

    def request_mc_shutdown(self):
        """ To ensure that lingering message channel
        connections are shut down when the client itself
        is shutting down.
        """
        d = self.callRemote(commands.JMShutdown)
        self.defaultCallbacks(d)
        return {'accepted': True}


    """DKG specifics
    """
    async def dkg_gen(self):
        jlog.debug(f'Coordinator call dkg_gen')
        client = self.factory.client
        md_type_idx = None
        session_id = None
        session = None

        while True:
            if md_type_idx is None:
                md_type_idx = await client.dkg_gen()
                if md_type_idx is None:
                    jlog.debug('finished dkg_gen execution')
                    break

            if session_id is None:
                session_id, _, session = self.dkg_init(*md_type_idx)
                if session_id is None:
                    jlog.warn('could not get session_id from dkg_init}')
                    await asyncio.sleep(5)
                    continue

            pub = await client.wait_on_dkg_output(session_id)
            if not pub:
                session_id = None
                session = None
                continue

            if session.dkg_output:
                md_type_idx = None
                session_id = None
                session = None
                client.dkg_gen_list.pop(0)
                continue

    def dkg_init(self, mixdepth, address_type, index):
        jlog.debug(f'Coordinator call dkg_init '
                   f'({mixdepth}, {address_type}, {index})')
        client = self.factory.client
        hostpubkeyhash, session_id, sig = client.dkg_init(mixdepth,
                                                          address_type, index)
        coordinator = client.dkg_coordinators.get(session_id)
        session = client.dkg_sessions.get(session_id)
        if session_id and session and coordinator:
            d = self.callRemote(commands.JMDKGInit,
                                hostpubkeyhash=hostpubkeyhash,
                                session_id=bintohex(session_id),
                                sig=sig)
            self.defaultCallbacks(d)
            session.dkg_init_sec = time.time()
            return session_id, coordinator, session
        return None, None, None

    @commands.JMDKGInitSeen.responder
    def on_JM_DKG_INIT_SEEN(self, nick, hostpubkeyhash, session_id, sig):
        wallet = self.client.wallet_service.wallet
        if not isinstance(wallet, FrostWallet) or wallet._dkg is None:
            return {'accepted': True}

        client = self.factory.client
        session_id = hextobin(session_id)
        nick, hostpubkeyhash, session_id, sig, pmsg1 = client.on_dkg_init(
            nick, hostpubkeyhash, session_id, sig)
        if pmsg1:
            d = self.callRemote(commands.JMDKGPMsg1,
                                nick=nick, hostpubkeyhash=hostpubkeyhash,
                                session_id=session_id, sig=sig,
                                pmsg1=base64.b64encode(pmsg1).decode('ascii'))
            self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMDKGPMsg1Seen.responder
    def on_JM_DKG_PMSG1_SEEN(self, nick, hostpubkeyhash,
                             session_id, sig, pmsg1):
        wallet = self.client.wallet_service.wallet
        if not isinstance(wallet, FrostWallet) or wallet._dkg is None:
            return {'accepted': True}

        client = self.factory.client
        bin_session_id = hextobin(session_id)
        pmsg1 = client.deserialize_pmsg1(base64.b64decode(pmsg1))
        ready_nicks, cmsg1 = client.on_dkg_pmsg1(nick, hostpubkeyhash,
                                                 bin_session_id, sig, pmsg1)
        if ready_nicks and cmsg1:
            for nick in ready_nicks:
                self.dkg_cmsg1(nick, session_id, cmsg1)
        return {'accepted': True}

    def dkg_cmsg1(self, nick, session_id, cmsg1):
        d = self.callRemote(commands.JMDKGCMsg1,
                            nick=nick, session_id=session_id,
                            cmsg1=base64.b64encode(cmsg1).decode('ascii'))
        self.defaultCallbacks(d)

    @commands.JMDKGPMsg2Seen.responder
    def on_JM_DKG_PMSG2_SEEN(self, nick, session_id, pmsg2):
        wallet = self.client.wallet_service.wallet
        if not isinstance(wallet, FrostWallet) or wallet._dkg is None:
            return {'accepted': True}

        client = self.factory.client
        bin_session_id = hextobin(session_id)
        pmsg2 = client.deserialize_pmsg2(base64.b64decode(pmsg2))
        ready_nicks, cmsg2, ext_recovery = client.on_dkg_pmsg2(
            nick, bin_session_id, pmsg2)
        if ready_nicks and cmsg2 and ext_recovery:
            for nick in ready_nicks:
                self.dkg_cmsg2(nick, session_id, cmsg2, ext_recovery)
        return {'accepted': True}

    def dkg_cmsg2(self, nick, session_id, cmsg2, ext_recovery):
        d = self.callRemote(commands.JMDKGCMsg2,
                            nick=nick, session_id=session_id,
                            cmsg2=base64.b64encode(cmsg2).decode('ascii'),
                            ext_recovery=ext_recovery.decode('ascii'))
        self.defaultCallbacks(d)

    @commands.JMDKGFinalizedSeen.responder
    def on_JM_DKG_FINALIZED_SEEN(self, nick, session_id):
        wallet = self.client.wallet_service.wallet
        if not isinstance(wallet, FrostWallet) or wallet._dkg is None:
            return {'accepted': True}

        client = self.factory.client
        bin_session_id = hextobin(session_id)
        jlog.debug(f'Coordinator get dkgfinalized')
        client.on_dkg_finalized(nick, bin_session_id)
        return {'accepted': True}

    @commands.JMDKGCMsg1Seen.responder
    def on_JM_DKG_CMSG1_SEEN(self, nick, session_id, cmsg1):
        wallet = self.client.wallet_service.wallet
        if not isinstance(wallet, FrostWallet) or wallet._dkg is None:
            return {'accepted': True}

        client = self.factory.client
        bin_session_id = hextobin(session_id)
        session = client.dkg_sessions.get(bin_session_id)
        if not session:
            jlog.error(f'on_JM_DKG_CMSG1_SEEN: session {session_id} not found')
            return {'accepted': True}
        if session and session.coord_nick == nick:
            cmsg1 = client.deserialize_cmsg1(base64.b64decode(cmsg1))
            pmsg2 = client.party_step2(bin_session_id, cmsg1)
            if pmsg2:
                pmsg2b64 = base64.b64encode(pmsg2).decode('ascii')
                d = self.callRemote(commands.JMDKGPMsg2,
                                    nick=nick, session_id=session_id,
                                    pmsg2=pmsg2b64)
                self.defaultCallbacks(d)
        else:
            jlog.error(f'on_JM_DKG_CMSG1_SEEN: not coordinator nick {nick}')
        return {'accepted': True}

    @commands.JMDKGCMsg2Seen.responder
    def on_JM_DKG_CMSG2_SEEN(self, nick, session_id, cmsg2, ext_recovery):
        wallet = self.client.wallet_service.wallet
        if not isinstance(wallet, FrostWallet) or wallet._dkg is None:
            return {'accepted': True}

        client = self.factory.client
        bin_session_id = hextobin(session_id)
        session = client.dkg_sessions.get(bin_session_id)
        if not session:
            jlog.error(f'on_JM_DKG_CMSG2_SEEN: session {session_id} not found')
            return {'accepted': True}
        if session and session.coord_nick == nick:
            cmsg2 = client.deserialize_cmsg2(base64.b64decode(cmsg2))
            finalized = client.finalize(bin_session_id, cmsg2,
                                        ext_recovery.encode('ascii'))
            if finalized:
                d = self.callRemote(commands.JMDKGFinalized,
                                    nick=nick, session_id=session_id)
                self.defaultCallbacks(d)
        else:
            jlog.error(f'on_JM_DKG_CMSG2_SEEN: not coordinator nick {nick}')
        return {'accepted': True}

    """FROST specifics
    """
    def frost_init(self, dkg_session_id, msg_bytes):
        jlog.debug(f'Coordinator call frost_init')
        client = self.factory.client
        hostpubkeyhash, session_id, sig = client.frost_init(
            dkg_session_id, msg_bytes)
        coordinator = client.frost_coordinators.get(session_id)
        session = client.frost_sessions.get(session_id)
        if session_id and session and coordinator:
            d = self.callRemote(commands.JMFROSTInit,
                                hostpubkeyhash=hostpubkeyhash,
                                session_id=bintohex(session_id),
                                sig=sig)
            self.defaultCallbacks(d)
            coordinator.frost_init_sec = time.time()
            return session_id, coordinator, session
        return None, None, None

    @commands.JMFROSTInitSeen.responder
    def on_JM_FROST_INIT_SEEN(self, nick, hostpubkeyhash, session_id, sig):
        wallet = self.client.wallet_service.wallet
        if not isinstance(wallet, FrostWallet) or wallet._dkg is None:
            return {'accepted': True}

        client = self.factory.client
        session_id = hextobin(session_id)
        nick, hostpubkeyhash, session_id, sig, pub_nonce = \
            client.on_frost_init(nick, hostpubkeyhash, session_id, sig)
        if pub_nonce:
            pub_nonce_b64 = base64.b64encode(pub_nonce).decode('ascii')
            d = self.callRemote(commands.JMFROSTRound1,
                                nick=nick, hostpubkeyhash=hostpubkeyhash,
                                session_id=session_id, sig=sig,
                                pub_nonce=pub_nonce_b64)
            self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMFROSTRound1Seen.responder
    def on_JM_FROST_ROUND1_SEEN(self, nick, hostpubkeyhash,
                                session_id, sig, pub_nonce):
        wallet = self.client.wallet_service.wallet
        if not isinstance(wallet, FrostWallet) or wallet._dkg is None:
            return {'accepted': True}

        client = self.factory.client
        bin_session_id = hextobin(session_id)
        pub_nonce = base64.b64decode(pub_nonce)
        ready_nicks, nonce_agg, dkg_session_id, ids, msg = \
            client.on_frost_round1(nick, hostpubkeyhash, bin_session_id,
                                   sig, pub_nonce)
        if ready_nicks and nonce_agg:
            for nick in ready_nicks:
                self.frost_agg1(nick, session_id, nonce_agg,
                                dkg_session_id, ids, msg)
        return {'accepted': True}

    def frost_agg1(self, nick, session_id,
                   nonce_agg, dkg_session_id, ids, msg):
        nonce_agg = base64.b64encode(nonce_agg).decode('ascii')
        dkg_session_id = base64.b64encode(dkg_session_id).decode('ascii')
        ids = ','.join([str(i)for i in ids])
        msg = base64.b64encode(msg).decode('ascii')
        d = self.callRemote(commands.JMFROSTAgg1,
                            nick=nick, session_id=session_id,
                            nonce_agg=nonce_agg, dkg_session_id=dkg_session_id,
                            ids=ids, msg=msg)
        self.defaultCallbacks(d)

    @commands.JMFROSTAgg1Seen.responder
    def on_JM_FROST_AGG1_SEEN(self, nick, session_id,
                              nonce_agg, dkg_session_id, ids, msg):
        wallet = self.client.wallet_service.wallet
        if not isinstance(wallet, FrostWallet) or wallet._dkg is None:
            return {'accepted': True}

        client = self.factory.client
        bin_session_id = hextobin(session_id)
        session = client.frost_sessions.get(bin_session_id)
        if not session:
            jlog.error(f'on_JM_DKG_AGG1_SEEN: session {session_id} not found')
            return {'accepted': True}
        if session and session.coord_nick == nick:
            nonce_agg = base64.b64decode(nonce_agg)
            dkg_session_id = base64.b64decode(dkg_session_id)
            ids = [int(i) for i in ids.split(',')]
            msg = base64.b64decode(msg)

            partial_sig = client.frost_round2(
                bin_session_id, nonce_agg, dkg_session_id, ids, msg)
            if partial_sig:
                partial_sig = base64.b64encode(partial_sig).decode('ascii')
                d = self.callRemote(commands.JMFROSTRound2,
                                    nick=nick, session_id=session_id,
                                    partial_sig=partial_sig)
                self.defaultCallbacks(d)
        else:
            jlog.error(f'on_JM_DKG_AGG1_SEEN: not coordinator nick {nick}')
        return {'accepted': True}

    @commands.JMFROSTRound2Seen.responder
    def on_JM_FROST_ROUND2_SEEN(self, nick, session_id, partial_sig):
        wallet = self.client.wallet_service.wallet
        if not isinstance(wallet, FrostWallet) or wallet._dkg is None:
            return {'accepted': True}

        client = self.factory.client
        bin_session_id = hextobin(session_id)
        partial_sig = base64.b64decode(partial_sig)
        sig = client.on_frost_round2(nick, bin_session_id, partial_sig)
        if sig:
            jlog.debug(f'Successfully get signature {sig.hex()[:8]}...')
        return {'accepted': True}


class JMMakerClientProtocol(JMClientProtocol):
    def __init__(self, factory, maker, nick_priv=None):
        self.factory = factory
        #used for keeping track of transactions for the unconf/conf callbacks
        self.finalized_offers = {}
        JMClientProtocol.__init__(self, factory, maker, nick_priv)

    @commands.JMUp.responder
    def on_JM_UP(self):
        if isinstance(self.client, DKGClient):
            self.client.on_jm_up()
        if isinstance(self.client, Maker):
            # wait until ready locally to submit offers (can be delayed
            # if wallet sync is slow).
            self.offers_ready_loop_counter = 0
            self.offers_ready_loop = task.LoopingCall(self.submitOffers)
            self.offers_ready_loop.start(2.0)
        return {'accepted': True}

    def submitOffers(self):
        self.offers_ready_loop_counter += 1
        if self.offers_ready_loop_counter == 300:
            jlog.info("Failed to start after 10 minutes, giving up.")
            self.offers_ready_loop.stop()
            reactor.stop()
        if not self.client.offerlist:
            return
        self.offers_ready_loop.stop()
        d = self.callRemote(commands.JMSetup,
                            role="MAKER",
                            initdata=self.client.offerlist,
                            use_fidelity_bond=(self.client.fidelity_bond is not None))
        self.defaultCallbacks(d)

    @commands.JMSetupDone.responder
    def on_JM_SETUP_DONE(self):
        jlog.info("JM daemon setup complete")
        return {'accepted': True}

    def clientStart(self):
        """Upon confirmation of network connection
        to daemon, request message channel initialization
        with relevant config data for our message channels
        """
        if self.client.aborted:
            return
        #needed only for naming convention in IRC currently
        blockchain_source = jm_single().config.get("BLOCKCHAIN",
                                                   "blockchain_source")
        #needed only for channel naming convention
        network = jm_single().config.get("BLOCKCHAIN", "network")
        chan_configs = self.factory.get_mchannels(mode="MAKER")
        #only here because Init message uses this field; not used by makers TODO
        minmakers = jm_single().config.getint("POLICY", "minimum_makers")
        maker_timeout_sec = jm_single().maker_timeout_sec

        d = self.callRemote(commands.JMInit,
                            bcsource=blockchain_source,
                            network=network,
                            chan_configs=chan_configs,
                            minmakers=minmakers,
                            maker_timeout_sec=maker_timeout_sec,
                            dust_threshold=jm_single().DUST_THRESHOLD,
                            blacklist_location=jm_single().commitment_list_location)
        self.defaultCallbacks(d)

    @commands.JMFidelityBondProofRequest.responder
    def on_JM_FIDELITY_BOND_PROOF_REQUEST(self, takernick, makernick):
        proof_msg = (self.client.fidelity_bond
            .create_proof(makernick, takernick)
            .create_proof_msg(self.client.fidelity_bond.cert_privkey))
        d = self.callRemote(commands.JMFidelityBondProof,
                nick=takernick,
                proof=proof_msg)
        self.defaultCallbacks(d)
        return {"accepted": True}

    @commands.JMAuthReceived.responder
    async def on_JM_AUTH_RECEIVED(self, nick, offer, commitment, revelation, amount,
                            kphex):
        retval = await self.client.on_auth_received(
                    nick, offer, commitment, revelation, amount, kphex)
        if not retval[0]:
            jlog.info("Maker refuses to continue on receiving auth.")
        else:
            utxos, auth_pub, cj_addr, change_addr, btc_sig = retval[1:]
            # json does not allow non-string keys:
            utxos_strkeyed = {}
            for k in utxos:
                success, u = utxo_to_utxostr(k)
                assert success
                utxos_strkeyed[u] = {"value": utxos[k]["value"],
                                     "address": utxos[k]["address"]}
            auth_pub_hex = bintohex(auth_pub)
            d = self.callRemote(commands.JMIOAuth,
                                nick=nick,
                                utxolist=utxos_strkeyed,
                                pubkey=auth_pub_hex,
                                cjaddr=cj_addr,
                                changeaddr=change_addr,
                                pubkeysig=btc_sig)
            self.defaultCallbacks(d)
        return {"accepted": True}

    @commands.JMTXReceived.responder
    async def on_JM_TX_RECEIVED(self, nick, tx, offer):
        retval = await self.client.on_tx_received(nick, tx, offer)
        if not retval[0]:
            jlog.info("Maker refuses to continue on receipt of tx")
        else:
            sigs = retval[1]
            self.finalized_offers[nick] = offer
            tx = btc.CMutableTransaction.deserialize(tx)
            self.finalized_offers[nick]["txd"] = tx
            # we index the callback by the out-set of the transaction,
            # because the txid is not known until all scriptSigs collected
            # (hence this is required for Makers, but not Takers).
            # For more info see WalletService.transaction_monitor():
            txinfo = tuple((x.scriptPubKey, x.nValue) for x in tx.vout)
            self.client.wallet_service.register_callbacks([self.unconfirm_callback],
                                              txinfo, "unconfirmed")
            self.client.wallet_service.register_callbacks([self.confirm_callback],
                                              txinfo, "confirmed")

            task.deferLater(reactor, float(jm_single().config.getint("TIMEOUT",
                            "unconfirm_timeout_sec")),
                            self.client.wallet_service.check_callback_called,
                            txinfo, self.unconfirm_callback, "unconfirmed",
                "transaction with outputs: " + str(txinfo) + " not broadcast.")

            d = self.callRemote(commands.JMTXSigs, nick=nick, sigs=sigs)
            self.defaultCallbacks(d)
        return {"accepted": True}

    @commands.JMTXBroadcast.responder
    def on_JM_TX_BROADCAST(self, tx):
        """ Makers have no issue broadcasting anything,
        so only need to prevent crashes.
        Note in particular we don't check the return value,
        since the transaction being accepted or not is not
        our (maker)'s concern.
        """
        try:
            jm_single().bc_interface.pushtx(tx)
        except:
            jlog.info("We received an invalid transaction broadcast "
                      "request: " + tx.hex())
        return {"accepted": True}

    def tx_match(self, txd):
        for k, v in self.finalized_offers.items():
            # Tx considered defined by its output set
            if v["txd"].vout == txd.vout:
                offerinfo = v
                break
        else:
            return False
        return offerinfo

    def unconfirm_callback(self, txd, txid):
        #find the offer for this tx
        offerinfo = self.tx_match(txd)
        if not offerinfo:
            return False
        to_cancel, to_announce = self.client.on_tx_unconfirmed(offerinfo,
                                                               txid)
        self.client.modify_orders(to_cancel, to_announce)

        txinfo = tuple((x.scriptPubKey, x.nValue) for x in txd.vout)
        confirm_timeout_sec = float(jm_single().config.get(
            "TIMEOUT", "confirm_timeout_hours")) * 3600
        task.deferLater(reactor, confirm_timeout_sec,
                        self.client.wallet_service.check_callback_called,
                        txinfo, self.confirm_callback, "confirmed",
        "transaction with outputs " + str(txinfo) + " not confirmed.")

        d = self.callRemote(commands.JMAnnounceOffers,
                            to_announce=to_announce,
                            to_cancel=to_cancel,
                            offerlist=self.client.offerlist)
        self.defaultCallbacks(d)
        return True

    def confirm_callback(self, txd, txid, confirms):
        #find the offer for this tx
        offerinfo = self.tx_match(txd)
        if not offerinfo:
            return False
        jlog.info('tx in a block: ' + txid + ' with ' + str(
            confirms) + ' confirmations.')
        to_cancel, to_announce = self.client.on_tx_confirmed(offerinfo,
                                                     txid, confirms)
        self.client.modify_orders(to_cancel, to_announce)
        d = self.callRemote(commands.JMAnnounceOffers,
                            to_announce=to_announce,
                            to_cancel=to_cancel,
                            offerlist=self.client.offerlist)
        self.defaultCallbacks(d)
        return True

class JMTakerClientProtocol(JMClientProtocol):

    def __init__(self, factory, client, nick_priv=None):
        self.orderbook = None
        JMClientProtocol.__init__(self, factory, client, nick_priv)

    def clientStart(self):
        """Upon confirmation of network connection
        to daemon, request message channel initialization
        with relevant config data for our message channels
        """
        if self.client.aborted:
            return
        #needed only for naming convention in IRC currently
        blockchain_source = jm_single().config.get("BLOCKCHAIN",
                                                   "blockchain_source")
        #needed only for channel naming convention
        network = jm_single().config.get("BLOCKCHAIN", "network")
        chan_configs = self.factory.get_mchannels(mode="TAKER")
        minmakers = jm_single().config.getint("POLICY", "minimum_makers")
        maker_timeout_sec = jm_single().maker_timeout_sec

        #To avoid creating yet another config variable, we set the timeout
        #to 20 * maker_timeout_sec.
        if not hasattr(self.client, 'testflag'): #pragma: no cover
            reactor.callLater(20*maker_timeout_sec, self.stallMonitor,
                          self.client.schedule_index+1)

        d = self.callRemote(commands.JMInit,
                            bcsource=blockchain_source,
                            network=network,
                            chan_configs=chan_configs,
                            minmakers=minmakers,
                            maker_timeout_sec=maker_timeout_sec,
                            dust_threshold=jm_single().DUST_THRESHOLD,
                            blacklist_location=jm_single().commitment_list_location)
        self.defaultCallbacks(d)

    async def stallMonitor(self, schedule_index):
        """Diagnoses whether long wait is due to any kind of failure;
        if so, calls the taker on_finished_callback with a failure
        flag so that the transaction can be re-tried or abandoned, as desired.
        Note that this *MUST* not trigger any action once the coinjoin transaction
        is seen on the network (hence waiting_for_conf).
        The schedule index parameter tells us whether the processing has moved
        on to the next item before we were woken up.
        """
        jlog.info("STALL MONITOR:")
        if self.client.aborted:
            jlog.info("Transaction was aborted.")
            return
        if not self.client.schedule_index == schedule_index:
            #TODO pre-initialize() ?
            jlog.info("No stall detected, continuing")
            return
        if self.client.waiting_for_conf:
            #Don't restart if the tx is already on the network!
            jlog.info("No stall detected, continuing")
            return
        if not self.client.txid:
            #txid is set on pushing; if it's not there, we have failed.
            jlog.info("Stall detected. Retrying transaction if possible ...")
            finished_cb_res = self.client.on_finished_callback(
                False, True, 0.0)
            if asyncio.iscoroutine(self.client.on_finished_callback):
                await finished_cb_res
        else:
            #This shouldn't really happen; if the tx confirmed,
            #the finished callback should already be called.
            jlog.info("Tx was already pushed; ignoring")

    @commands.JMUp.responder
    def on_JM_UP(self):
        d = self.callRemote(commands.JMSetup,
                            role="TAKER",
                            initdata=None,
                            use_fidelity_bond=False)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMSetupDone.responder
    def on_JM_SETUP_DONE(self):
        jlog.info("JM daemon setup complete")
        #The daemon is ready and has requested the orderbook
        #from the pit; we can request the entire orderbook
        #and filter it as we choose.
        reactor.callLater(jm_single().maker_timeout_sec, self.get_offers)
        return {'accepted': True}

    @commands.JMFillResponse.responder
    async def on_JM_FILL_RESPONSE(self, success, ioauth_data):
        """Receives the entire set of phase 1 data (principally utxos)
        from the counterparties and passes through to the Taker for
        tx construction. If there were sufficient makers, data is passed
        over for exactly those makers that responded. If not, the list
        of non-responsive makers is added to the permanent "ignored_makers"
        list, but the Taker processing is bypassed and the transaction
        is abandoned here (so will be picked up as stalled in multi-join
        schedules).
        In the first of the above two cases, after the Taker processes
        the ioauth data and returns the proposed
        transaction, passes the phase 2 initiating data to the daemon.
        """
        if not success:
            jlog.info("Makers who didnt respond: " + str(ioauth_data))
            self.client.add_ignored_makers(ioauth_data)
            return {'accepted': True}
        else:
            jlog.info("Makers responded with: " + str(ioauth_data))
            retval = await self.client.receive_utxos(ioauth_data)
            if not retval[0]:
                jlog.info("Taker is not continuing, phase 2 abandoned.")
                jlog.info("Reason: " + str(retval[1]))
                if len(self.client.schedule) == 1:
                    # see comment for the same invocation in on_JM_OFFERS;
                    # the logic here is the same.
                    finished_cb_res = self.client.on_finished_callback(
                        False, False, 0.0)
                    if asyncio.iscoroutine(self.client.on_finished_callback):
                        await finished_cb_res
                return {'accepted': False}
            else:
                nick_list, tx = retval[1:]
                reactor.callLater(0, self.make_tx, nick_list, tx)
                return {'accepted': True}

    @commands.JMOffers.responder
    async def on_JM_OFFERS(self, orderbook, fidelitybonds):
        self.orderbook = json.loads(orderbook)
        fidelity_bonds_list = json.loads(fidelitybonds)
        #Removed for now, as judged too large, even for DEBUG:
        #jlog.debug("Got the orderbook: " + str(self.orderbook))
        retval = await self.client.initialize(
            self.orderbook, fidelity_bonds_list)
        #format of retval is:
        #True, self.cjamount, commitment, revelation, self.filtered_orderbook)
        if not retval[0]:
            jlog.info("Taker not continuing after receipt of orderbook")
            if len(self.client.schedule) == 1:
                #In single sendpayments, allow immediate quit.
                #This could be an optional feature also for multi-entry schedules,
                #but is not the functionality desired in general (tumbler).
                finished_cb_res = self.client.on_finished_callback(
                    False, False, 0.0)
                if asyncio.iscoroutine(self.client.on_finished_callback):
                    await finished_cb_res
            return {'accepted': True}
        elif retval[0] == "commitment-failure":
            #This case occurs if we cannot find any utxos for reasons
            #other than age, which is a permanent failure
            finished_cb_res = self.client.on_finished_callback(
                False, False, 0.0)
            if asyncio.iscoroutine(self.client.on_finished_callback):
                await finished_cb_res
            return {'accepted': True}
        amt, cmt, rev, foffers = retval[1:]
        d = self.callRemote(commands.JMFill,
                            amount=amt,
                            commitment=str(cmt),
                            revelation=str(rev),
                            filled_offers=foffers)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMSigReceived.responder
    async def on_JM_SIG_RECEIVED(self, nick, sig):
        retval = await self.client.on_sig(nick, sig)
        if retval:
            nick_to_use, tx = retval
            self.push_tx(nick_to_use, tx)
        return {'accepted': True}

    def get_offers(self):
        d = self.callRemote(commands.JMRequestOffers)
        self.defaultCallbacks(d)

    def push_tx(self, nick_to_push, tx):
        d = self.callRemote(commands.JMPushTx, nick=str(nick_to_push), tx=tx)
        self.defaultCallbacks(d)

class SNICKERClientProtocolFactory(protocol.ClientFactory):
    protocol = SNICKERClientProtocol
    def buildProtocol(self, addr):
        return self.protocol(self.client, self.servers, oneshot=self.oneshot)
    def __init__(self, client, servers, oneshot=False):
        self.client = client
        self.servers = servers
        self.oneshot = oneshot

class BIP78ClientProtocolFactory(protocol.ClientFactory):
    protocol = BIP78ClientProtocol
    def buildProtocol(self, addr):
        return self.protocol(self.manager, self.params,
                    self.success_callback,
                    self.failure_callback,
                    tls_whitelist=self.tls_whitelist,
                    mode=self.mode)
    def __init__(self, manager, params, success_callback,
                 failure_callback, tls_whitelist=[],
                 mode="sender"):
        self.manager = manager
        self.params = params
        self.success_callback = success_callback
        self.failure_callback = failure_callback
        self.tls_whitelist = tls_whitelist
        self.mode = mode

class JMClientProtocolFactory(protocol.ClientFactory):
    protocol = JMTakerClientProtocol

    def __init__(self, client, proto_type="TAKER"):
        self.client = client
        self.proto_client = None
        self.proto_type = proto_type
        if self.proto_type == "MAKER":
            self.protocol = JMMakerClientProtocol

    def setClient(self, client):
        self.proto_client = client

    def getClient(self):
        return self.proto_client

    def buildProtocol(self, addr):
        return self.protocol(self, self.client)

    def get_mchannels(self, mode):
        """ A transparent wrapper that allows override,
        so that a script can return a customised set of
        message channel configs; currently used for testing
        multiple bots on regtest.
        """
        return get_mchannels(mode)

def start_reactor(host, port, factory=None, snickerfactory=None,
                  bip78=False, jm_coinjoin=True, ish=True,
                  daemon=False, rs=True, gui=False): #pragma: no cover
    #(Cannot start the reactor in tests)
    #Not used in prod (twisted logging):
    #startLogging(stdout)
    global daemon_serving_host
    global daemon_serving_port

    # in case we are starting connections but not the
    # reactor, we can return a handle to the connections so
    # that they can be cleaned up properly.
    # TODO: currently *only* used in tests, with only one
    # server protocol listening.
    serverconn = None
    clientconn = None

    usessl = jm_single().config.get("DAEMON", "use_ssl") != 'false'
    jmcport, snickerport, bip78port = [port]*3
    if daemon:
        try:
            from jmdaemon import JMDaemonServerProtocolFactory, start_daemon, \
                 SNICKERDaemonServerProtocolFactory, BIP78ServerProtocolFactory
        except ImportError:
            jlog.error("Cannot start daemon without jmdaemon package; "
                       "either install it, and restart, or, if you want "
                       "to run the daemon separately, edit the DAEMON "
                       "section of the config. Quitting.")
            return
        if jm_coinjoin:
            dfactory = JMDaemonServerProtocolFactory()
        if snickerfactory:
            sdfactory = SNICKERDaemonServerProtocolFactory()
        if bip78:
            bip78factory = BIP78ServerProtocolFactory()
        # ints are immutable in python, to pass by ref we use
        # an array object:
        port_a = [port]
        def start_daemon_on_port(p, f, name, port_offset):
            orgp = p[0]
            while True:
                try:
                    serverconn = start_daemon(host, p[0] - port_offset, f, usessl,
                        './ssl/key.pem', './ssl/cert.pem')
                    jlog.info("{} daemon listening on port {}".format(
                        name, str(p[0] - port_offset)))
                    break
                except Exception:
                    jlog.warn("Cannot listen on port " + str(
                        p[0] - port_offset) + ", trying next port")
                    if p[0] >= (orgp + 100):
                        jlog.error("Tried 100 ports but cannot "
                                   "listen on any of them. Quitting.")
                        twisted_sys_exit(EXIT_FAILURE)
                    p[0] += 1
            return (p[0], serverconn)

        if jm_coinjoin:
            # TODO either re-apply this port incrementing logic
            # to other protocols, or re-work how the ports work entirely.
            jmcport, serverconn = start_daemon_on_port(port_a, dfactory,
                                                       "Joinmarket", 0)
            daemon_serving_port = jmcport
            daemon_serving_host = host
        # (See above) For now these other two are just on ports that are 1K offsets.
        if snickerfactory:
            snickerport, serverconn = start_daemon_on_port(port_a, sdfactory,
                                                    "SNICKER", 1000)
            snickerport = snickerport - 1000
        if bip78:
            start_daemon_on_port(port_a, bip78factory, "BIP78", 2000)

        # if the port had to be incremented due to conflict above, we should update
        # it in the config var so e.g. bip78 connections choose the port we actually
        # used.
        # This is specific to the daemon-in-same-process case; for the external daemon
        # the user must just set the right value.
        jm_single().config.set("DAEMON", "daemon_port", str(port_a[0]))

    # Note the reactor.connect*** entries do not include BIP78 which
    # starts in jmclient.payjoin:
    if usessl:
        if factory:
            reactor.connectSSL(host, jmcport, factory, ClientContextFactory())
        if snickerfactory:
            reactor.connectSSL(host, snickerport, snickerfactory,
                               ClientContextFactory())
    else:
        if factory:
            clientconn = reactor.connectTCP(host, jmcport, factory)
        if snickerfactory:
            reactor.connectTCP(host, snickerport, snickerfactory)
    if rs:
        if not gui:
            reactor.run(installSignalHandlers=ish)
        if isinstance(jm_single().bc_interface, RegtestBitcoinCoreInterface):
            jm_single().bc_interface.shutdown_signal = True
    return (serverconn, clientconn)
