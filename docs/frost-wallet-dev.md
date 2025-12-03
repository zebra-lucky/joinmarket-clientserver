# FROST P2TR wallet development details

**NOTE**: minimal python version is python3.12

## FrostWallet storages
`FrostWallet` have two additional storages in addtion to wallet `Storage`:
- `DKGStorage` with DKG data
- `DKGRecoveryStorage` with DKG recovery data (unencrypted)

They are loaded only for DKG/FROST support and not loaded on usual wallet
usage.

Usual wallet usage interact with FROST/DKG functionality via IPC code in
`frost_ipc.py` (currently `AF_UNIX` socket for simplicity).

`jmclient.wallet_utils.open_wallet` has two new parameters:
- `load_dkg=False`: by default do not load `DKGStorage`
- `dkg_read_only=True`: load `DKGStorage` for read only commands

Additionally `open_wallet` params `read_only` and `dkg_read_only` can not
be mutually unset by design.


## Structure of DKG data in the DKGStorage

```
"dkg": {
    "sessions": {
        "md_type_idx": session_id,
        ...
    },
    "pubkey": {
        "session_id": threshold_pubkey,
        ...
    },
    "pubshares": {
        "session_id": [pubshare1, pubshare2, ...],
        ...
    },
    "secshare": {
        "session_id": secshare,
        ...
    },
    "hostpubkeys": {
        "session_id": [hostpubkey1, hostpubkey2, ...],
        ...
    },
    "t": {
        "session_id": t,
        ...
    }
}
```
Where `md_type_idx` is a serialization in bytes of `mixdepth`, `address_type`,
`index` of pubkey as in the HD wallet derivations.

## Overall information
In the code used twisted `asyncioreactor` in place of standard twisted reactor.
Initialization is done as early as possible in `jmclient/__init__.py`.
Classes for wallets: `TaprootWallet`, `FrostWallet` in the `jmclient/wallet.py`
Utility class `DKGManager` in the `jmclient/wallet.py`.
Engine classes `BTC_P2TR(BTCEngine)`, `BTC_P2TR_FROST(BTC_P2TR)` in the
`jmclient/cryptoengine.py`.

## `scripts/wallet-tool.py` commands

- `hostpubkey`: display host public key
- `servefrost`: run only as DKG/FROST support (separate process which need
to be run permanently)
- `dkgrecover`: recover DKG sessions from DKG recovery file
- `dkgls`: display FrostWallet DKG data
- `dkgrm`: rm FrostWallet DKG data by `session_id` list
- `recdkgls`: display Recovery DKG File data
- `recdkgrm`: rm Recovery DKG File data by `session_id` list
- `testdkg`: run only as test of DKG process
- `testfrost`: run only as test of FROST signing

## Description of `jmclient/frost_clients.py`

- `class DKGClient`: clent which support only DKG sessions over JM channels.
Uses `chilldkg` reference code from
https://github.com/BlockstreamResearch/bip-frost-dkg/, placed in the
`jmfrost/chilldkg_ref` package.

Uses channel level commands `dkginit`, `dkgpmsg1`, `dkgcmsg1`, `dkgpmsg2`,
`dkgcmsg2`, `dkgfinalized`, added to `jmdaemon/protocol.py`.

NOTE: `dkgfinalized` is used to ensure all DKG party saw `dkgcmsg2` and
saved DKG data to wallet/recovery data.

Commands in the `jmbase/commands.py`: `JMDKGInit`, `JMDKGPMsg1`, `JMDKGCMsg1`,
`JMDKGPMsg2`, `MDKGCMsg2`, `JMDKGFinalized`, `JMDKGInitSeen`, `JMDKGPMsg1Seen`,
`JMDKGCMsg1Seen`, `JMDKGPMsg2Seen`, `JMDKGCMsg2Seen`, `JMDKGFinalizedSeen`.

Responders on the commands in the `jmclient/client_protocol.py`,
`jmdaemon/daemon_protocol.py`.

In the DKG sessions the party which need new pubkey is named Coordinator.

- `class FROSTClient(DKGClient)`: clent which support DKG/FROST sessions over
JM channels. Uses reference FROST code from
https://github.com/siv2r/bip-frost-signing/, placed in the
`jmfrost/frost_ref` package.

Uses channel level commands `frostreq`, `frostack`, `frostinit`, `frostround1`,
`frostagg1`, `frostround2`, added to `jmdaemon/protocol.py`.

Commands in the `jmbase/commands.py`: `JMFROSTReq`, `JMFROSTAck`,
`JMFROSTInit`, `JMFROSTRound1`, `JMFROSTAgg1`, `JMFROSTRound2`,
`JMFROSTReqSeen`, `JMFROSTAckSeen`, `JMFROSTInitSeen`, `JMFROSTRound1Seen`,
`JMFROSTAgg1Seen`, `JMFROSTRound2Seen`.

Responders on the commands in the `jmclient/client_protocol.py`,
`jmdaemon/daemon_protocol.py`.

In the FROST sessions the party which need new signature is named Coordinator.

## Details on DKG message channel commands

| Coordinator |      | Party |
| :---------:|:----:|:-------:|
|!dkginit (public)|>>>||
||<<<|!dkgpmsg1 (private unencrypted)|
|!dkgcmsg1 (private unencrypted)|>>>||
||<<<|!dkgpmsg2 (private unencrypted)|
|!dkgcmsg2 (private unencrypted)|>>>||
||<<<|!dkgfinalied (private unencrypted)|

**dkginit**: public broadcast command from coordinator to request DKG
exchange

```
self.mcc.pubmsg(f'!dkginit {hostpubkeyhash} {session_id} {sig}')
```

- `hostpubkeyhash`: sha256 hash of wallet `hostpubkey` to identify
wallet to other DKG parties
- `session_id`: random 32 bytes to identify DKG session
- `sig`: Schnorr signature on `session_id` to verify with `hostpubkey` to
authenticate wallet

**dkgpmsg1**: private unencrypted command from parties to authenticate and
send EncPedPop `pmsg1` to coordinator

```
msg = f'{hostpubkeyhash} {session_id} {sig} {pmsg1}'
self.mcc.prepare_privmsg(nick, "dkgpmsg1", msg)
```

- `hostpubkeyhash`: sha256 hash of wallet `hostpubkey` to identify
wallet to coordinator
- `session_id`: 32 bytes to idenify DKG session
- `sig`: Schnorr signature on `session_id` to verify with `hostpubkey` to
authenticate wallet
- `pmsg1`: EncPedPop participants step1 message

**dkgcmsg1**: private unencrypted command from coordinator to send
EncPedPop `cmsg1` to DKG parties

```
msg = f'{session_id} {cmsg1}'
self.mcc.prepare_privmsg(nick, "dkgcmsg1", msg)
```

- `session_id`: 32 bytes to idenify DKG session
- `cmsg1`: EncPedPop coordinator step1 message

**dkgpmsg2**: private unencrypted command from parties to send
EncPedPop `pmsg2` to coordinator

```
msg = f'{session_id} {pmsg2}'
self.mcc.prepare_privmsg(nick, "dkgpmsg2", msg)
```

- `session_id`: 32 bytes to idenify DKG session
- `pmsg2`: EncPedPop participants step2 message

**dkgcmsg2**: private unencrypted command from coordinator to send
EncPedPop `cmsg2` and encrypted `ext_recovery` to DKG parties

```
msg = f'{session_id} {cmsg2} {ext_recovery}'
self.mcc.prepare_privmsg(nick, "dkgcmsg2", msg)
```

- `session_id`: 32 bytes to idenify DKG session
- `cmsg2`: EncPedPop coordinator step2 message
- `ext_recovery`: byte encoded and encrypted with `hostpubkey` tuple
`(mixdepth, address_type, index)`, which sent to DKG parties to write
with DKG recovery data

**dkgfinalized**: private unencrypted command from parties to coordinator
to confirm DKG session finished and all DKG data saved together with
`recovery data`, `ext_recovery`

```
msg = f'{session_id}'
self.mcc.prepare_privmsg(nick, "dkgfinalized", msg)
```

- `session_id`: 32 bytes to idenify DKG session

## Details on FROST message channel commands

| Coordinator |      | Party |
| :---------:|:----:|:-------:|
|!frostreq (public)|>>>||
||<<<|!frostack (private unencrypted)|
|!frostinit (private encrypted)|>>>||
||<<<|!frostround1 (private encrypted)|
|!frostagg1 (private encrypted)|>>>||
||<<<|!frostround2 (private encrypted)|

**frostreq**: public broadcast command from coordinator to request encrypted
FROST exchange

```
req_msg = f'!frostreq {hostpubkeyhash} {sig} {session_id} {dh_pubk}'
self.mcc.pubmsg(req_msg)
```

- `hostpubkeyhash`: sha256 hash of wallet `hostpubkey` to identify
wallet to other FROST parties
- `sig`: Schnorr signature on `session_id` to verify with `hostpubkey` to
authenticate wallet
- `session_id`: random 32 bytes to identify FROST session
- `dh_pubk`: ECDH public key to create encrypted private messages for other
FROST commands

**frostack**: private unencrypted command from parties to acknowledge encrypted
FROST exchange

```
ack_msg = f'{hostpubkeyhash} {sig} {session_id} {dh_pubk}
self.mcc.prepare_privmsg(nick, 'frostack', ack_msg)
```

- `hostpubkeyhash`: sha256 hash of wallet `hostpubkey` to identify
wallet for coordinator
- `sig`: Schnorr signature on `session_id` to verify with `hostpubkey` to
authenticate wallet
- `session_id`: 32 bytes to idenify FROST session
- `dh_pubk`: ECDH public key to create encrypted private messages for other
FROST commands

**frostinit**: private encrypted command from coordinator to initiate
FROST exchange

```
init_msg = f'{session_id}'
self.mcc.prepare_privmsg(nick, 'frostinit', init_msg)
```

- `session_id`: 32 bytes to idenify FROST session

**frostround1**: private encrypted command from parties to send `pub_nonce`
part of FROST exchange

```
round1_msg = f'{session_id} pub_nonce}'
self.mcc.prepare_privmsg(nick, "frostround1", round1_msg)
```

- `session_id`: 32 bytes to idenify FROST session
- `pub_nonce`: public part of `sec_nonce`/`pub_nonce` pair

**frostagg1**: private encrypted command from coorinator to send aggregated
nonces data, DKG session id to get key data, ids of sign parties and
message to sign

```
agg1_msg = f'{session_id} {nonce_agg} {dkg_session_id} {ids} {msg}'
self.mcc.prepare_privmsg(nick, "frostagg1", agg1_msg)
```

- `session_id`: 32 bytes to idenify FROST session
- `nonce_agg`: aggregated pub nonces data
- `dkg_session_id`: bytes to idenify DKG session where key data for FROST
whas generated
- `ids`: FROST sign parties ids
- `msg`: 32 bytes message to sign

**frostround2**: private encrypted command from parties to send partial
signature for coordinator

```
msg = f'{session_id} {partial_sig}'
self.mcc.prepare_privmsg(nick, "frostround2", msg)
```

- `session_id`: 32 bytes to idenify FROST session
- `partial_sig`: partial FROST signature agregated later on coordinator

## Recovery storage, recovery data file.
ChillDKG recovery data is placed in the unencrypted recovery file with
the name `wallet.jmdat.dkg_recovery`. Code of `class DKGRecoveryStorage` is
placed in `jmclient/storage.py`

## Utility scripts
Currently changes in the code allow creation of unencrypted wallets, if
empty password is used.
- `scripts/bdecode.py`: allow decode wallet/recovery data files to stdout.
- `scripts/bencode.py`: allow allow encode text file to bencode format.
Separate options is presented to encode with DKG data file magic or DKG
recovery data file magic.
