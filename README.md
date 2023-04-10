# Decentraland crypto (Rust)

A rust library to create and verify Decentraland AuthChain

## Install

```bash
 cargo add dcl-crypto
```

## Tes

To run test you need to provide a ethereum rpc endpoint using the environment ``

```bash
export ETHEREUM_MAINNET_RPC="https://mainnet.infura.io/v3/00000000000000000000000000000000"
cargo test --doc
```

## Release

> :warning: Do not modify `package.version` on `Cargo.toml`

Use [Github Releases](https://github.com/decentraland/decentraland-crypto-rust/releases) to create a new version.

## TODO

- [x] serialize and deserialize auth chains
- [x] verify auth chains
  - [x] simple
  - [x] ephemeral
- [x] verify auth chain expiration
- [x] verify personal signatures
- [ ] verify [EIP-1271](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1271.md) signatures
- [ ] create identity
- [ ] create auth chain from identity
- [ ] load identity from file
- [ ] release process
  - [x] build cache
  - [ ] coverage
  - [ ] publish cargo
