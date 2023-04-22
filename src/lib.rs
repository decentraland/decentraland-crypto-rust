/*!
 * This crate is a port of the original [`@dcl/crypto`](https://github.com/decentraland/decentraland-crypto)
 * implemented on javascript and provides the necessary tools to create and validate
 * Decentraland's Authentication Chains.
 *
 * ## Usage
 *
 * This crate is [on crates.io](https://crates.io/crates/dcl_crypto) and can be
 * used by adding `dcl_crypto` to your dependencies in your project's `Cargo.toml`.
 *
 * ```toml
 * [dependencies]
 * dcl_crypto = "0"
 * ```
 *
 * ## Verify a signature
 *
 * To verify a signature using a authentication chain, you need the [`Authenticator`](authenticator/struct.Authenticator.html)
 * and the [`AuthChain`](chain/struct.AuthChain.html) structs.
 *
 * The `Authenticator` is the one that will verify the two types of signatures that
 * can be present on an authchain:
 * - The signature of the wallet's owner, also referred as personal signature.
 * - The signature of the smart contract wallet, described on the [EIP-1271](https://eips.ethereum.org/EIPS/eip-1271).
 *
 * In order to verify the signature of the smart contract wallet, the `Authenticator`
 * needs a web3 provider to call the contract.
 *
 * ```rust
 * use dcl_crypto::Authenticator;
 *
 * let endpoint = std::env::var("ETHEREUM_MAINNET_RPC").unwrap();
 * let transport = web3::transports::Http::new(&endpoint).unwrap();
 * let authenticator = Authenticator::with_transport(&transport);
 * ```
 *
 * If you don't need to verify the signature of the smart contract wallet, you can create
 * an `Authenticator` without a web3 provider using the [`Authenticator::new()`](authenticator/struct.Authenticator.html#method.new)
 * method.
 *
 * ```rust
 * use dcl_crypto::Authenticator;
 *
 * let authenticator = Authenticator::new();
 * ```
 *
 * Once you have an `Authenticator` you can verify if a given message was signed by the `AuthChain` using the [`verify_signature`](authenticator/struct.Authenticator.html#method.verify_signature) method.
 *
 * ```rust
 * use dcl_crypto::{Authenticator, AuthChain};
 *
 * let authenticator = Authenticator::new();
 * let auth_chain = AuthChain::from_json(r#"[
 *   {
 *     "type": "SIGNER",
 *     "payload": "0x84452bbfa4ca14b7828e2f3bbd106a2bd495cd34",
 *     "signature": ""
 *   },
 *   {
 *     "type": "ECDSA_EPHEMERAL",
 *     "payload": "Decentraland Login\nEphemeral address: 0xB80549D339DCe9834271EcF5F1F1bb141C70AbC2\nExpiration: 2123-03-20T12:36:25.522Z",
 *     "signature": "0x76bf8d3c8ee6798bd488c4bc7ac1298d0ad78759669be39876e63ccfd9af81e31b8c6d8000b892ed2d17eb2f5a2b56fc3edbbf33c6089d3e5148d83cc70ce9001c"
 *   },
 *   {
 *     "type": "ECDSA_SIGNED_ENTITY",
 *     "payload": "QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo",
 *     "signature": "0xd71fb5511f7d9116d171a12754b2c6f4c795240bee982511049a14aba57f18684b48a08413ab00176801d773eab0436fff5d0c978877b6d05f483ee2ae36efb41b"
 *   }
 * ]"#).unwrap();
 *
 * authenticator.verify_signature(&auth_chain, "QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo"); // future
 * ```
 */
pub mod account;
pub mod authenticator;
pub mod chain;
pub mod rpc;

pub use account::Address;
pub use chain::{AuthChain, AuthLink};
pub use authenticator::Authenticator;