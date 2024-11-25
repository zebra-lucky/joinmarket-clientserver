# FROST P2TR wallet usage

**NOTE**: minimal python version is python3.12

To use FROST P2TR wallet you need (example for 2 of 3 FROST signing):

1. Add `txindex=1` to `bitcoin.conf`. This options is need to get non-wallet
transactions with `getrawtransaction`. This data is need to perform signing
of P2TR inputs.

2. Set `frost = true` in the `POLICY` section of `joinmarket.cfg`:
```
[POLICY]
...
# Use FROST P2TR SegWit wallet
frost = true
```

3. Create bitcoind watchonly descriptors wallet:
```
bitcoin-cli createwallet "wallet_name" true true
```
where `true true` is:
> `disable_private_keys`
> Disable the possibility of private keys
> (only watchonlys are possible in this mode).

> `blank`
> Create a blank wallet. A blank wallet has no keys or HD seed.

4. Get `hostpubkey` for wallet by running:
```
scripts/wallet-tool.py wallet.jmdat hostpubkey
...
021e99d8193b95da10f514556e98882bc2cebfd0ee0711fa71006cbc9e9a135b43
```

5. Repeat steps 1-4 for other FROST group wallets.

6. Gather hostpubkeys from step 4 and place to the `FROST` section
of `joinmarket.cfg` as the `hostpubkeys` value separated by `,`.

7. Add `t` (threshold) value to the `FROST` section of `joinmarket.cfg`:
```
[FROST]
hostpubkeys = 021e99d8193b95da...,03a2f4ce928da0f5...,02a1e2ee50187f3e...
t = 2
```

8. Run permanent FROST processes with `servefrost` command on `wallet1`,
`wallet2`, `wallet3`:
```
scripts/wallet-tool.py wallet.jmdat servefrost
```

9. Run `display` command on `wallet1`
```
scripts/wallet-tool.py wallet.jmdat display
```
The process of DKG sessions will start to generate pubkeys for the
wallet addresses. This can take several minutes.

10. Repeat step 9 to generate pubkeys for `wallet2`, `wallet3`.

11. Test FROST signing with `testfrost` command
```
scripts/wallet-tool.py wallet.jmdat testfrost
```
