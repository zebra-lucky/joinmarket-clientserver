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
`dkgcmsg2`, `dkgfinalized` added to `jmdaemon/protocol.py`.

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

Uses channel level commands `frostinit`, `frostround1`, `frostround2`,
`frostagg1` added to `jmdaemon/protocol.py`.

Commands in the `jmbase/commands.py`: `JMFROSTInit`, `JMFROSTRound1`,
`JMFROSTAgg1`, `JMFROSTRound2`, `JMFROSTInitSeen`, `JMFROSTRound1Seen`,
`JMFROSTAgg1Seen`, `JMFROSTRound2Seen`.

Responders on the commands in the `jmclient/client_protocol.py`,
`jmdaemon/daemon_protocol.py`.

In the FROST sessions the party which need new signature is named Coordinator.

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
