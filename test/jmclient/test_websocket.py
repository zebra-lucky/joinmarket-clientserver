
import os
import json
from twisted.internet import reactor, task
from twisted.internet.defer import inlineCallbacks, Deferred
from twisted.trial import unittest
from autobahn.twisted.websocket import WebSocketClientFactory, \
    WebSocketClientProtocol, connectWS, listenWS

from jmbase import get_log, hextobin
from jmbase.support import get_free_tcp_ports
from jmclient import (JmwalletdWebSocketServerFactory,
                      JmwalletdWebSocketServerProtocol)
from jmclient.auth import JMTokenAuthority
from jmbitcoin import CTransaction

testdir = os.path.dirname(os.path.realpath(__file__))
jlog = get_log()

# example transaction for sending a notification with:
test_tx_hex_1 = "02000000000102578770b2732aed421ffe62d54fd695cf281ca336e4f686d2adbb2e8c3bedb2570000000000ffffffff4719a259786b4237f92460629181edcc3424419592529103143090f07d85ec330100000000ffffffff0324fd9b0100000000160014d38fa4a6ac8db7495e5e2b5d219dccd412dd9bae24fd9b0100000000160014564aead56de8f4d445fc5b74a61793b5c8a819667af6c208000000001600146ec55c2e1d1a7a868b5ec91822bf40bba842bac502473044022078f8106a5645cc4afeef36d4addec391a5b058cc51053b42c89fcedf92f4db1002200cdf1b66a922863fba8dc1b1b1a0dce043d952fa14dcbe86c427fda25e930a53012102f1f750bfb73dbe4c7faec2c9c301ad0e02176cd47bcc909ff0a117e95b2aad7b02483045022100b9a6c2295a1b0f7605381d416f6ed8da763bd7c20f2402dd36b62dd9dd07375002207d40eaff4fc6ee219a7498abfab6bdc54b7ce006ac4b978b64bff960fbf5f31e012103c2a7d6e44acdbd503c578ec7d1741a44864780be0186e555e853eee86e06f11f00000000"
test_tx_hex_txid = "ca606efc5ba8f6669ba15e9262e5d38e745345ea96106d5a919688d1ff0da0cc"

# Shared JWT token authority for test:
token_authority = JMTokenAuthority()


class ServerTProtocol(JmwalletdWebSocketServerProtocol):

    def onMessage(self, payload, isBinary):
        super().onMessage(payload, isBinary)
        self.factory.on_message_d.callback(None)


class ClientTProtocol(WebSocketClientProtocol):
    """
    Simple client that connects to a WebSocket server, send a HELLO
    message every 2 seconds and print everything it receives.
    """

    ACCESS_TOKEN = token_authority.issue()["token"].encode("utf8")

    def sendAuth(self):
        """Our server will not broadcast to us unless we authenticate."""
        self.sendMessage(self.ACCESS_TOKEN)

    def onOpen(self):
        # auth on startup
        self.sendAuth()
        # for test, monitor how many times we
        # were notified.
        self.factory.notifs = 0

    def onMessage(self, payload, isBinary):
        if not isBinary:
            payload = payload.decode("utf-8")
            jlog.info("Text message received: {}".format(payload))
        self.factory.notifs += 1
        self.factory.on_message_d.callback(None)
        # ensure we got the transaction message expected:
        deser_notif = json.loads(payload)
        assert deser_notif["txid"] == test_tx_hex_txid
        assert deser_notif["txdetails"]["txid"] == test_tx_hex_txid


class WebsocketTestBase(object):
    """ This tests that a websocket client can connect to our
    websocket subscription service
    """
    # the port for the ws (auto)
    wss_port = None
    
    def setUp(self):
        if self.wss_port is None:
            free_ports = get_free_tcp_ports(1)
            self.wss_port = free_ports[0]
        self.wss_url = "ws://127.0.0.1:" + str(self.wss_port)
        self.wss_factory = JmwalletdWebSocketServerFactory(self.wss_url, token_authority)
        self.wss_factory.protocol = ServerTProtocol
        self.wss_factory.on_message_d = Deferred()
        self.listeningport = listenWS(self.wss_factory, contextFactory=None)
        self.test_tx = CTransaction.deserialize(hextobin(test_tx_hex_1))

    def stopListening(self):
        return self.listeningport.stopListening()

    @inlineCallbacks
    def do_test(self):
        self.client_factory = WebSocketClientFactory("ws://127.0.0.1:"+str(self.wss_port))
        self.client_factory.on_message_d = Deferred()

        self.client_factory.protocol = ClientTProtocol
        # keep track of the connector object so we can close it manually:
        self.client_connector = connectWS(self.client_factory)

        # wait on server to receive message
        yield self.wss_factory.on_message_d

        yield self.fire_tx_notif()
        # wait on client to receive message
        yield self.client_factory.on_message_d

        assert self.client_factory.notifs == 1

    @inlineCallbacks
    def fire_tx_notif(self):
        yield self.wss_factory.sendTxNotification(
            self.test_tx, test_tx_hex_txid)

    def tearDown(self):
        reactor.disconnectAll()
        for dc in reactor.getDelayedCalls():
            if not dc.cancelled:
                dc.cancel()
        self.client_connector.disconnect()
        return self.stopListening()


class TrialTestWS(WebsocketTestBase, unittest.TestCase):

    @inlineCallbacks
    def test_basic_notification(self):
        yield self.do_test()
