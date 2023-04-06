use futures::future::BoxFuture;
use thiserror::Error;
use web3::{
    signing::{hash_message, recover, RecoveryError},
    Error as Web3Error, RequestId, Transport, Web3,
};

use crate::{
    account::Address,
    chain::{AuthChain, AuthLink},
    rpc::{rpc_call_is_valid_signature, RPCCallError},
};

#[derive(Debug, Error)]
pub enum AuthenticatorError {
    #[error("malformed authchain: expecting at least 2 links, but is empty")]
    EmptyChain,

    #[error("malformed authchain: expecting SIGNER at position {position}, but found {found}")]
    SignerExpected { position: usize, found: String },

    #[error("malformed authchain: expecting ECDSA_EPHEMERAL or ECDSA_EIP_1654_EPHEMERAL at position {position}, but found {found}")]
    EphemeralExpected { position: usize, found: String },

    #[error("malformed authchain: expecting ECDSA_SIGNED_ENTITY or ECDSA_EIP_1654_SIGNED_ENTITY at position {position}, but found {found}")]
    SignedEntityExpected { position: usize, found: String },

    #[error("malformed authchain: expecting ECDSA_SIGNED_ENTITY or ECDSA_EIP_1654_SIGNED_ENTITY")]
    SignedEntityMissing,

    #[error("fail to validate {kind} at position {position}: {message}")]
    ValidationError {
        position: usize,
        kind: String,
        message: String,
    },

    #[error("unexpected authority at position {position}: expected {expected}, but found {found}")]
    UnexpectedSigner {
        position: usize,
        expected: Address,
        found: Address,
    },

    #[error(
        "unexpected last authority at position {position}: expected {expected}, but found {found}"
    )]
    UnexpectedLastAuthority {
        position: usize,
        expected: String,
        found: String,
    },
}

#[derive(Debug, Clone)]
pub struct WithoutTransport {}
impl Transport for WithoutTransport {
    type Out = BoxFuture<'static, Result<serde_json::Value, Web3Error>>;

    fn prepare(&self, _method: &str, _params: Vec<serde_json::Value>) -> (usize, jsonrpc_core::types::request::Call) {
        unimplemented!()
    }

    fn send(&self, _id: RequestId, _request: jsonrpc_core::Call) -> Self::Out {
        unimplemented!()
    }
}

/// Validates a message and has correspond to an address.
///
/// ```
/// use decentraland_crypto::authenticator::Authenticator;
/// use decentraland_crypto::account::Address;
/// use decentraland_crypto::chain::AuthChain;
///
/// # tokio_test::block_on(async {
///     let authenticator = Authenticator::new();
///
///     let chain = AuthChain::parse(r#"[
///       {
///         "type": "SIGNER",
///         "payload": "0x84452bbfa4ca14b7828e2f3bbd106a2bd495cd34",
///         "signature": ""
///       },
///       {
///         "type": "ECDSA_EPHEMERAL",
///         "payload": "Decentraland Login\nEphemeral address: 0x8b7E12dBE632f22D6B2c5Fc6789E02d27896Cb43\nExpiration: 2023-05-03T11:52:56.132Z",
///         "signature": "0x42f5f7bc74c2934e6608627fa72a6078d470bfb12eb75063f5e4c878e176a5f265389606415a8dbe1b0914e75d58a2440840c5de3f325b8a5026dd8db0b397451b"
///       },
///       {
///         "type": "ECDSA_SIGNED_ENTITY",
///         "payload": "signed message",
///         "signature": "0x60d35a5a5d0bacc7d5439101b1c502b175c6f35b3f3dea00ed2d81445f3ece0e796e8175a90a2ec4826d7baea44fc297c881c9163c9247daa9c347cd81c41a781c"
///       }
///     ]"#).unwrap();
///
///     let address =  Address::try_from("0x84452bbfa4ca14b7828e2f3bbd106a2bd495cd34").unwrap();
///     let owner =  chain.owner().unwrap();
///     let result = authenticator.verify(&chain, "signed message").await.unwrap();
///     assert_eq!(result, &address);
///     assert_eq!(result, owner);
/// # })
/// ```
pub struct Authenticator<T> {
    transport: Option<T>,
}

impl Authenticator<()> {
    pub fn new() -> Authenticator<WithoutTransport> {
        Authenticator { transport: None }
    }

    pub fn with_transport<T: Transport>(transport: T) -> Authenticator<T> {
        Authenticator {
            transport: Some(transport),
        }
    }
}

impl Authenticator<WithoutTransport> {
    pub fn add_transport<T: Transport>(&self, transport: T) -> Authenticator<T> {
        Authenticator {
            transport: Some(transport),
        }
    }
}

impl<T: Transport> Authenticator<T> {
    async fn validate_eip1654(
        &self,
        address: Address,
        message: String,
        hash: Vec<u8>,
    ) -> Result<bool, RPCCallError> {
        if let Some(transport) = &self.transport {
            rpc_call_is_valid_signature(&Web3::new(transport).eth(), address, message, hash).await
        } else {
            Err(RPCCallError::NotImplemented)
        }
    }

    fn validate_personal(
        &self,
        address: Address,
        message: String,
        hash: Vec<u8>,
    ) -> Result<bool, RecoveryError> {
        if hash.len() != 65 {
            return Err(RecoveryError::InvalidSignature);
        }

        let signature = hash.get(..=63).ok_or(RecoveryError::InvalidSignature)?;
        let recovery_id = *hash.last().ok_or(RecoveryError::InvalidSignature)?;
        let h160 = recover(
            hash_message(message).as_bytes(),
            signature,
            (recovery_id as i32) - 27,
        )?;

        println!("{} == {}", address, h160);
        Ok(address == h160)
    }

    async fn verify_signer<'a>(
        &self,
        link: &'a AuthLink,
        position: usize,
    ) -> Result<&'a Address, AuthenticatorError> {
        match link {
            AuthLink::Signer { payload, .. } => Ok(payload),
            _ => Err(AuthenticatorError::SignerExpected {
                position,
                found: link.kind().to_string(),
            }),
        }
    }

    async fn verify_ephemeral<'a>(
        &self,
        authority: &'a Address,
        link: &'a AuthLink,
        position: usize,
    ) -> Result<&'a Address, AuthenticatorError> {
        match link {
            AuthLink::EcdsaPersonalEphemeral { payload, signature } => {
                let result = self
                    .validate_personal(authority.clone(), payload.to_string(), signature.to_vec())
                    .map_err(|err| AuthenticatorError::ValidationError {
                        position,
                        kind: link.kind().to_string(),
                        message: err.to_string(),
                    })?;

                if !result {
                    return Err(AuthenticatorError::ValidationError {
                        position,
                        kind: link.kind().to_string(),
                        message: format!(
                            "Signature {} couldn't be validated against address {}",
                            signature, authority
                        ),
                    });
                }

                Ok(&payload.address)
            }
            AuthLink::EcdsaEip1654Ephemeral { payload, signature } => {
                let result = self
                    .validate_eip1654(authority.clone(), payload.to_string(), signature.to_vec())
                    .await
                    .map_err(|err| AuthenticatorError::ValidationError {
                        position,
                        kind: link.kind().to_string(),
                        message: err.to_string(),
                    })?;

                if !result {
                    return Err(AuthenticatorError::ValidationError {
                        position,
                        kind: link.kind().to_string(),
                        message: format!(
                            "Signature {} couldn't be validated against address {}",
                            signature, authority
                        ),
                    });
                }

                Ok(&payload.address)
            }
            _ => Err(AuthenticatorError::EphemeralExpected {
                position,
                found: link.kind().to_string(),
            }),
        }
    }

    async fn verify_signed_entity<'a>(
        &self,
        authority: &'a Address,
        link: &'a AuthLink,
        position: usize,
    ) -> Result<&'a str, AuthenticatorError> {
        match link {
            AuthLink::EcdsaPersonalSignedEntity { payload, signature } => {
                let result = self
                    .validate_personal(authority.clone(), payload.to_string(), signature.to_vec())
                    .map_err(|err| AuthenticatorError::ValidationError {
                        position,
                        kind: link.kind().to_string(),
                        message: err.to_string(),
                    })?;

                if !result {
                    return Err(AuthenticatorError::ValidationError {
                        position,
                        kind: link.kind().to_string(),
                        message: format!(
                            "Signature {} couldn't be validated against address {}",
                            signature, authority
                        ),
                    });
                }

                Ok(payload)
            }
            AuthLink::EcdsaEip1654SignedEntity { payload, signature } => {
                let result = self
                    .validate_eip1654(authority.clone(), payload.to_string(), signature.to_vec())
                    .await
                    .map_err(|err| AuthenticatorError::ValidationError {
                        position,
                        kind: link.kind().to_string(),
                        message: err.to_string(),
                    })?;

                if !result {
                    return Err(AuthenticatorError::ValidationError {
                        position,
                        kind: link.kind().to_string(),
                        message: format!(
                            "Signature {} couldn't be validated against address {}",
                            signature, authority
                        ),
                    });
                }

                Ok(payload)
            }
            _ => Err(AuthenticatorError::SignedEntityExpected {
                position,
                found: link.kind().to_string(),
            }),
        }
    }

    pub async fn verify<'a>(
        &self,
        chain: &'a AuthChain,
        last_authority: &str,
    ) -> Result<&'a Address, AuthenticatorError> {
        let owner = match chain.first() {
            Some(link) => self.verify_signer(link, 0).await?,
            None => return Err(AuthenticatorError::EmptyChain),
        };

        let len = chain.len();

        let mut latest_authority = owner;
        for (position, link) in chain.iter().enumerate().skip(1) {
            // is not the last link
            if position != len - 1 {
                latest_authority = self
                    .verify_ephemeral(latest_authority, link, position)
                    .await?;

                // is the last link
            } else {
                let signed_message = self
                    .verify_signed_entity(latest_authority, link, position)
                    .await?;

                if signed_message == last_authority {
                    return Ok(owner);
                } else {
                    return Err(AuthenticatorError::UnexpectedLastAuthority {
                        position,
                        found: signed_message.to_string(),
                        expected: last_authority.to_string(),
                    });
                }
            }
        }

        Err(AuthenticatorError::SignedEntityMissing)
    }
}
