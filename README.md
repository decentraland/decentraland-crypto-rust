# Decentraland crypto (Rust)

A rust library to create and verify Decentraland AuthChain

## Install

```bash
 cargo add dcl-crypto
```

## Test

To run all tests you need to provide a ethereum rpc endpoint.

First, create a `.cargo/config.toml` file using the template provided in the repository and set your rpc provider.

```bash
cp .cargo/config.toml.example .cargo/config.toml
```

Once configured you can run all tests

```bash
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
