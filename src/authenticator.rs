use futures::Future;
use thiserror::Error;
use web3::{
    signing::{hash_message, recover, RecoveryError},
    Error as Web3Error,
};

use crate::{
    account::Address,
    chain::{AuthChain, AuthLink},
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

    #[error("ECDSA_EPHEMERAL or ECDSA_SIGNED_ENTITY cannot be validated because personal validator is not implemented")]
    PersonalValidatorNotImplemented,

    #[error("ECDSA_EIP_1654_EPHEMERAL or ECDSA_EIP_1654_SIGNED_ENTITY cannot be validated because eip1654 validator is not implemented")]
    EIP1654ValidatorNotImplemented,

    #[error("validation error: {0}")]
    ValidationError(String),

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

impl From<RecoveryError> for AuthenticatorError {
    fn from(value: RecoveryError) -> Self {
        AuthenticatorError::ValidationError(value.to_string())
    }
}

impl From<Web3Error> for AuthenticatorError {
    fn from(value: Web3Error) -> Self {
        AuthenticatorError::ValidationError(value.to_string())
    }
}

type SignatureValidator =
    Box<dyn Fn(Address, String, Vec<u8>) -> SignatureValidatorResult + Send + Sync + 'static>;
type SignatureValidatorResult =
    Box<dyn Future<Output = Result<bool, AuthenticatorError>> + Send + 'static>;

/// Validates a message and has correspond to an address.
///
/// ```
/// use dcl_crypto::authenticator::Authenticator;
/// use dcl_crypto::account::Address;
/// use dcl_crypto::chain::AuthChain;
///
/// # tokio_test::block_on(async {
///     let authenticator = Authenticator::default();
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
#[derive(Default)]
pub struct Authenticator {
    eip1654_validator: Option<SignatureValidator>,
}

impl Authenticator {
    pub fn with_eip1654_validator<H, R>(mut self, validator: H) -> Self
    where
        H: Fn(Address, String, Vec<u8>) -> R + Send + Sync + 'static,
        R: Future<Output = Result<bool, AuthenticatorError>> + Send + 'static,
    {
        self.eip1654_validator = Some(Box::new(move |address, message, hash| {
            Box::new(validator(address, message, hash))
        }));
        self
    }

    async fn validate_with(
        validator: &SignatureValidator,
        address: Address,
        message: String,
        hash: Vec<u8>,
    ) -> Result<bool, AuthenticatorError> {
        let validation = validator(address, message, hash);
        Box::into_pin(validation).await
    }

    /// Validates a message and has correspond to an address.
    ///
    /// ```
    /// use dcl_crypto::authenticator::Authenticator;
    /// use dcl_crypto::account::{Address, PersonalSignature};
    ///
    /// # tokio_test::block_on(async {
    ///     let address = Address::try_from("0xb92702b3EeFB3c2049aEB845B0335b283e11E9c6").unwrap();
    ///     let message = "Decentraland Login\nEphemeral address: 0xF5E49370d9754924C9f082077ec6ad49F3113150\nExpiration: 2023-05-02T02:20:12.026Z".to_string();
    ///     let hash = PersonalSignature::try_from("0xb2985d12400f9ee87091156b5951ee0e745efda50f503bbdcee3a3e7fc8adbb051b20ce386f7b400ae5865e7263c6a7155decda1af433287bceff911994849e81c").unwrap().to_vec();
    ///
    ///     let result = Authenticator::validate_personal(address, message, hash).unwrap();
    ///     assert_eq!(result, true);
    /// # })
    /// ```
    pub fn validate_personal(
        address: Address,
        message: String,
        hash: Vec<u8>,
    ) -> Result<bool, AuthenticatorError> {
        if hash.len() != 65 {
            return Err(RecoveryError::InvalidSignature.into());
        }

        let signature = hash.get(..=63).ok_or(RecoveryError::InvalidSignature)?;
        let recovery_id = *hash.last().ok_or(RecoveryError::InvalidSignature)?;
        let h160 = recover(
            hash_message(message).as_bytes(),
            signature,
            (recovery_id as i32) - 27,
        )?;

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
                Authenticator::validate_personal(
                    authority.clone(),
                    payload.to_string(),
                    signature.to_vec(),
                )?;

                Ok(&payload.address)
            }
            AuthLink::EcdsaEip1654Ephemeral { payload, signature } => {
                if let Some(eip1654_validator) = &self.eip1654_validator {
                    Authenticator::validate_with(
                        eip1654_validator,
                        authority.clone(),
                        payload.to_string(),
                        signature.to_vec(),
                    )
                    .await?;
                    Ok(&payload.address)
                } else {
                    Err(AuthenticatorError::EIP1654ValidatorNotImplemented)
                }
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
                Authenticator::validate_personal(
                    authority.clone(),
                    payload.to_string(),
                    signature.to_vec(),
                )?;

                Ok(payload)
            }
            AuthLink::EcdsaEip1654SignedEntity { payload, signature } => {
                if let Some(eip1654_validator) = &self.eip1654_validator {
                    Authenticator::validate_with(
                        eip1654_validator,
                        authority.clone(),
                        payload.to_string(),
                        signature.to_vec(),
                    )
                    .await?;
                    Ok(payload)
                } else {
                    Err(AuthenticatorError::EIP1654ValidatorNotImplemented)
                }
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

        let mut latest_authority = &Address::default();
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
