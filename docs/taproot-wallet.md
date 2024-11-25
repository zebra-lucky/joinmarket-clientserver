# Taproot P2TR wallet usage

To use P2TR wallet you need:

1. Add `txindex=1` to `bitcoin.conf`. This options is need to get non-wallet
transactions with `getrawtransaction`. This data is need to perform signing
of P2TR inputs.

2. Set `taproot = true` in the `POLICY` section of `joinmarket.cfg`:
```
[POLICY]
...
# Use Taproot P2TR SegWit wallet
taproot = true
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
