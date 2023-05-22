use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use thiserror::Error;
use web3::{
    signing::{hash_message, recover, RecoveryError},
    Error as Web3Error, RequestId, Transport, Web3,
};

use crate::{
    account::{Address, PersonalSignature},
    chain::{AuthChain, AuthLink},
    util::{rpc_call_is_valid_signature, RPCCallError},
    Identity,
};

#[derive(Debug, Error, PartialEq)]
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

    #[error("expired entity {kind} at position {position}")]
    ExpiredEntity { position: usize, kind: String },
}

#[derive(Debug, Clone)]
pub struct WithoutTransport {}
impl Transport for WithoutTransport {
    type Out = BoxFuture<'static, Result<serde_json::Value, Web3Error>>;

    fn prepare(
        &self,
        _method: &str,
        _params: Vec<serde_json::Value>,
    ) -> (usize, jsonrpc_core::types::request::Call) {
        unimplemented!()
    }

    fn send(&self, _id: RequestId, _request: jsonrpc_core::Call) -> Self::Out {
        unimplemented!()
    }
}

/// Validates a message and has correspond to an address.
///
/// ```rust
/// use dcl_crypto::authenticator::Authenticator;
/// use dcl_crypto::account::Address;
/// use dcl_crypto::chain::AuthChain;
///
/// # tokio_test::block_on(async {
///     let authenticator = Authenticator::new();
///
///     let chain = AuthChain::from_json(r#"[
///        {
///            "type": "SIGNER",
///            "payload": "0x84452bbfa4ca14b7828e2f3bbd106a2bd495cd34",
///            "signature": ""
///        },
///        {
///            "type": "ECDSA_EPHEMERAL",
///            "payload": "Decentraland Login\r\nEphemeral address: 0xB80549D339DCe9834271EcF5F1F1bb141C70AbC2\r\nExpiration: 2123-03-20T12:36:25.522Z",
///            "signature": "0x76bf8d3c8ee6798bd488c4bc7ac1298d0ad78759669be39876e63ccfd9af81e31b8c6d8000b892ed2d17eb2f5a2b56fc3edbbf33c6089d3e5148d83cc70ce9001c"
///        },
///        {
///            "type": "ECDSA_SIGNED_ENTITY",
///            "payload": "QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo",
///            "signature": "0xd71fb5511f7d9116d171a12754b2c6f4c795240bee982511049a14aba57f18684b48a08413ab00176801d773eab0436fff5d0c978877b6d05f483ee2ae36efb41b"
///        }
///     ]"#).unwrap();
///
///     let address =  Address::try_from("0x84452bbfa4ca14b7828e2f3bbd106a2bd495cd34").unwrap();
///     let owner =  chain.owner().unwrap();
///     let result = authenticator.verify_signature(&chain, "QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo").await.unwrap();
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

    /// Validates a message and has correspond to an address.
    ///
    /// ```
    /// use dcl_crypto::authenticator::Authenticator;
    /// use dcl_crypto::account::{Address, PersonalSignature};
    ///
    /// # tokio_test::block_on(async {
    ///     let address = Address::try_from("0x84452bbfa4ca14b7828e2f3bbd106a2bd495cd34").unwrap();
    ///     let message = "Decentraland Login\nEphemeral address: 0xe94944439fAB988e5e14b128BbcF6D5502b05f9C\nExpiration: 2020-02-20T00:00:00.000Z";
    ///     let hash = PersonalSignature::try_from("0x2d45e2a3e9e04614cf6bb822951b849458a78037733202d4bda12e60ef1ff4d266b02af7b72caa232c45052520fd440869672da2b0966b29fff21638e3d21ca01b").unwrap().to_vec();
    ///
    ///     let result = Authenticator::new().validate_personal(&address, &message, &hash).unwrap();
    ///     assert_eq!(result, true);
    /// # })
    /// ```
    pub fn validate_personal<M: AsRef<[u8]>>(
        &self,
        address: &Address,
        message: M,
        hash: &[u8],
    ) -> Result<bool, RecoveryError> {
        if hash.len() != 65 {
            return Err(RecoveryError::InvalidSignature);
        }

        let signature = &hash[..64];
        let recovery_id = &hash[64];

        let recovery_number = (recovery_id - 27) as i32;
        let h160 = recover(hash_message(message).as_bytes(), signature, recovery_number)?;

        Ok(address == h160)
    }

    /// Verifies that and authlink is a signer and returns it as result. Otherwise, returns an error.
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

    /// Verifies:
    /// - the authlink is an ephemeral link (personal or eip1654)
    /// - the ephemeral link is not expired
    /// - the ephemeral payload is valid
    /// - the ephemeral signature corresponds to the authority
    ///
    /// returns the address defined in the ephemeral payload, otherwise returns an error.
    async fn verify_ephemeral<'a, 'l, 'd>(
        &self,
        authority: &'a Address,
        link: &'l AuthLink,
        expiration: &'d DateTime<Utc>,
        position: usize,
    ) -> Result<&'l Address, AuthenticatorError> {
        match link {
            AuthLink::EcdsaPersonalEphemeral { payload, signature } => {
                if payload.is_expired_at(expiration) {
                    return Err(AuthenticatorError::ExpiredEntity {
                        position,
                        kind: link.kind().to_string(),
                    });
                }

                let result = self
                    .validate_personal(authority, payload.to_string(), signature.as_ref())
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
                if payload.is_expired_at(expiration) {
                    return Err(AuthenticatorError::ExpiredEntity {
                        position,
                        kind: link.kind().to_string(),
                    });
                }

                let result = self
                    .validate_eip1654(*authority, payload.to_string(), signature.to_vec())
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

    /// Verifies:
    /// - the authlink is an ephemeral link (personal or eip1654)
    /// - the ephemeral link is not expired
    /// - the ephemeral signature corresponds to the authority
    ///
    /// returns the signed payload, otherwise returns an error.
    async fn verify_signed_entity<'a>(
        &self,
        authority: &'a Address,
        link: &'a AuthLink,
        position: usize,
    ) -> Result<&'a str, AuthenticatorError> {
        match link {
            AuthLink::EcdsaPersonalSignedEntity { payload, signature } => {
                let result = self
                    .validate_personal(authority, payload, signature.as_ref())
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
                    .validate_eip1654(*authority, payload.to_string(), signature.to_vec())
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

    /// Verifies and authchain is valid, not expired at a given date and corresponds to the last_authority, otherwise, returns an error.
    pub async fn verify_signature_at<'a>(
        &self,
        chain: &'a AuthChain,
        last_authority: &str,
        expiration: &DateTime<Utc>,
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
                    .verify_ephemeral(latest_authority, link, expiration, position)
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

    /// Verifies and authchain is valid, not expired and corresponds to the last_authority, otherwise, returns an error.
    pub async fn verify_signature<'a>(
        &self,
        chain: &'a AuthChain,
        last_authority: &str,
    ) -> Result<&'a Address, AuthenticatorError> {
        let now = &Utc::now();
        self.verify_signature_at(chain, last_authority, now).await
    }

    /// Creates a personal signature from a given identity and payload.
    /// This method is intended to maintain parity with the [JS implementation](https://github.com/decentraland/decentraland-crypto/blob/680d7cceb52a75bfae38269005614e577f48561a/src/Authenticator.ts#L185).
    pub fn create_signature<M: AsRef<str>>(
        &self,
        identity: &Identity,
        payload: M,
    ) -> PersonalSignature {
        identity.create_signature(payload)
    }

    /// Creates an authchain from a given identity and payload.
    /// This method is intended to maintain parity with the [JS implementation](https://github.com/decentraland/decentraland-crypto/blob/680d7cceb52a75bfae38269005614e577f48561a/src/Authenticator.ts#L171).
    pub fn sign_payload<M: AsRef<str>>(&self, identity: &Identity, payload: M) -> AuthChain {
        identity.sign_payload(payload)
    }
}

#[cfg(test)]
mod test {
    use crate::account::{Account, Signer};

    use super::*;
    use std::env;

    #[tokio::test]
    async fn test_should_validate_personal_signature() {
        let authenticator = Authenticator::new();
        let chain = AuthChain::from_json(r#"[
            {
              "type": "SIGNER",
              "payload": "0x84452bbfa4ca14b7828e2f3bbd106a2bd495cd34",
              "signature": ""
            },
            {
              "type": "ECDSA_EPHEMERAL",
              "payload": "Decentraland Login\nEphemeral address: 0xB80549D339DCe9834271EcF5F1F1bb141C70AbC2\nExpiration: 2123-03-20T12:36:25.522Z",
              "signature": "0x76bf8d3c8ee6798bd488c4bc7ac1298d0ad78759669be39876e63ccfd9af81e31b8c6d8000b892ed2d17eb2f5a2b56fc3edbbf33c6089d3e5148d83cc70ce9001c"
            },
            {
              "type": "ECDSA_SIGNED_ENTITY",
              "payload": "QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo",
              "signature": "0xd71fb5511f7d9116d171a12754b2c6f4c795240bee982511049a14aba57f18684b48a08413ab00176801d773eab0436fff5d0c978877b6d05f483ee2ae36efb41b"
            }
          ]"#).unwrap();

        let owner = authenticator
            .verify_signature(&chain, "QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo")
            .await
            .unwrap();
        let expected = &Address::try_from("0x84452bbfa4ca14b7828e2f3bbd106a2bd495cd34").unwrap();
        assert_eq!(owner, expected);
    }

    #[tokio::test]
    async fn test_should_validate_eip_1654_signatures() {
        let endpoint = env::var("ETHEREUM_MAINNET_RPC").unwrap();
        let transport = web3::transports::Http::new(&endpoint).unwrap();
        let authenticator = Authenticator::with_transport(&transport);
        let chain = AuthChain::from_json(r#"[
            {
              "type": "SIGNER",
              "payload": "0x8C889222833F961FC991B31d15e25738c6732930",
              "signature": ""
            },
            {
              "type": "ECDSA_EIP_1654_EPHEMERAL",
              "payload": "Decentraland Login\nEphemeral address: 0x4A1b9FD363dE915145008C41FA217377B2C223F2\nExpiration: 2123-03-18T16:59:36.515Z",
              "signature": "0x00050203596af90cecdbf9a768886e771178fd5561dd27ab005d000100019dde76f11e2c6aff01f6548f3046a9d0c569e13e79dec4218322068d3123e1162167fabd84dccfaabd350b93d2405f7b8a9cef4846b4d9a55d17838809a0e2591b020101c50adeadb7fe15bee45dcb820610cdedcd314eb0030102640dccefda3685e6c0dbeb70c1cf8018c27077eb00021cfbe892a1b29ac5e2fda1038c7965656be94aec57b658582f16447089bcf50b09df216a7e21d861cd7474723a7bfc70bf1caa55a962476cf78eb4b54471018b1b020103d9e87370ededc599df3bf9dd0e48586005f1a1bb"
            },
            {
              "type": "ECDSA_SIGNED_ENTITY",
              "payload": "QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo",
              "signature": "0xb962b57accc8e12083769339888f82752d13f280012b2c7b2aa2722eae103aea7a623dc88605bf7036ec8c23b0bb8f036b52f5e4e30ee913f6f2a077d5e5e3e01b"
            }
          ]"#).unwrap();

        let owner = authenticator
            .verify_signature(&chain, "QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo")
            .await
            .unwrap();
        let expected = &Address::try_from("0x8C889222833F961FC991B31d15e25738c6732930").unwrap();
        assert_eq!(owner, expected);
    }

    #[tokio::test]
    async fn test_should_validate_simple_personal_signatures() {
        let authenticator = Authenticator::new();
        let signer = Address::try_from("0xeC6E6c0841a2bA474E92Bf42BaF76bFe80e8657C").unwrap();
        let payload = "QmWyFNeHbxXaPtUnzKvDZPpKSa4d5anZEZEFJ8TC1WgcfU";
        let signature = "0xaaafb0368c13c42e401e71162cb55a062b3b0a5389e0740e7dc34e623b12f0fd65e2fadac51ab5f0de8f69b1311f23f1f218753e8a957043a2a789ba721141f91c";
        let chain = AuthChain::simple(signer, payload, signature).unwrap();

        let owner = authenticator
            .verify_signature(&chain, "QmWyFNeHbxXaPtUnzKvDZPpKSa4d5anZEZEFJ8TC1WgcfU")
            .await
            .unwrap();
        let expected = &Address::try_from("0xeC6E6c0841a2bA474E92Bf42BaF76bFe80e8657C").unwrap();
        assert_eq!(owner, expected);
    }

    #[tokio::test]
    async fn test_should_validate_simple_eip_1654_signatures() {
        let endpoint = env::var("ETHEREUM_MAINNET_RPC").unwrap();
        let transport = web3::transports::Http::new(&endpoint).unwrap();
        let authenticator = Authenticator::with_transport(&transport);

        let signer = Address::try_from("0x6b7d7e82c984a0F4489c722fd11906F017f57704").unwrap();
        let payload = "QmNUd7Cyoo9CREGsACkvBrQSb3KjhWX379FVsdjTCGsTAz";
        let signature = "0x7fba0fbe75d0b28a224ec49ad99f6025f9055880db9ed1a35bc527a372c54ebe2461406aa07097bc47017da4319e19e517c49952697f074bcdc702f36afa72b01c759138c6ca4675367458884eb9b820c51af60a79efe1904ebcf2c1950fc7a2c02f3595a82ea1cc9d67a680c2f9b34df6abf5b344e857773dfe4210c6f85405151b";
        let chain = AuthChain::simple(signer, payload, signature).unwrap();

        let owner = authenticator
            .verify_signature(&chain, "QmNUd7Cyoo9CREGsACkvBrQSb3KjhWX379FVsdjTCGsTAz")
            .await
            .unwrap();
        let expected = &Address::try_from("0x6b7d7e82c984a0F4489c722fd11906F017f57704").unwrap();
        assert_eq!(owner, expected);
    }

    #[tokio::test]
    async fn test_should_support_r_on_personal_signatures() {
        let authenticator = Authenticator::new();
        let chain = AuthChain::from_json(r#"[
            {
              "type": "SIGNER",
              "payload": "0x84452bbfa4ca14b7828e2f3bbd106a2bd495cd34",
              "signature": ""
            },
            {
              "type": "ECDSA_EPHEMERAL",
              "payload": "Decentraland Login\r\nEphemeral address: 0xB80549D339DCe9834271EcF5F1F1bb141C70AbC2\r\nExpiration: 2123-03-20T12:36:25.522Z",
              "signature": "0x76bf8d3c8ee6798bd488c4bc7ac1298d0ad78759669be39876e63ccfd9af81e31b8c6d8000b892ed2d17eb2f5a2b56fc3edbbf33c6089d3e5148d83cc70ce9001c"
            },
            {
              "type": "ECDSA_SIGNED_ENTITY",
              "payload": "QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo",
              "signature": "0xd71fb5511f7d9116d171a12754b2c6f4c795240bee982511049a14aba57f18684b48a08413ab00176801d773eab0436fff5d0c978877b6d05f483ee2ae36efb41b"
            }
          ]"#).unwrap();

        let owner = authenticator
            .verify_signature(&chain, "QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo")
            .await
            .unwrap();
        let expected = &Address::try_from("0x84452bbfa4ca14b7828e2f3bbd106a2bd495cd34").unwrap();
        assert_eq!(owner, expected);
    }

    #[tokio::test]
    async fn test_should_support_r_on_eip_1654_signatures() {
        let endpoint = env::var("ETHEREUM_MAINNET_RPC").unwrap();
        let transport = web3::transports::Http::new(&endpoint).unwrap();
        let authenticator = Authenticator::with_transport(&transport);
        let chain = AuthChain::from_json(r#"[
            {
              "type": "SIGNER",
              "payload": "0x8C889222833F961FC991B31d15e25738c6732930",
              "signature": ""
            },
            {
              "type": "ECDSA_EIP_1654_EPHEMERAL",
              "payload": "Decentraland Login\r\nEphemeral address: 0x4A1b9FD363dE915145008C41FA217377B2C223F2\r\nExpiration: 2123-03-18T16:59:36.515Z",
              "signature": "0x00050203596af90cecdbf9a768886e771178fd5561dd27ab005d000100019dde76f11e2c6aff01f6548f3046a9d0c569e13e79dec4218322068d3123e1162167fabd84dccfaabd350b93d2405f7b8a9cef4846b4d9a55d17838809a0e2591b020101c50adeadb7fe15bee45dcb820610cdedcd314eb0030102640dccefda3685e6c0dbeb70c1cf8018c27077eb00021cfbe892a1b29ac5e2fda1038c7965656be94aec57b658582f16447089bcf50b09df216a7e21d861cd7474723a7bfc70bf1caa55a962476cf78eb4b54471018b1b020103d9e87370ededc599df3bf9dd0e48586005f1a1bb"
            },
            {
              "type": "ECDSA_SIGNED_ENTITY",
              "payload": "QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo",
              "signature": "0xb962b57accc8e12083769339888f82752d13f280012b2c7b2aa2722eae103aea7a623dc88605bf7036ec8c23b0bb8f036b52f5e4e30ee913f6f2a077d5e5e3e01b"
            }
          ]"#).unwrap();

        let owner = authenticator
            .verify_signature(&chain, "QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo")
            .await
            .unwrap();
        let expected = &Address::try_from("0x8C889222833F961FC991B31d15e25738c6732930").unwrap();
        assert_eq!(owner, expected);
    }

    #[tokio::test]
    async fn test_should_fail_it_tries_to_verify_a_eip_1654_signatures_without_a_transport() {
        let chain = AuthChain::from_json(r#"[
            {
              "type": "SIGNER",
              "payload": "0x8C889222833F961FC991B31d15e25738c6732930",
              "signature": ""
            },
            {
              "type": "ECDSA_EIP_1654_EPHEMERAL",
              "payload": "Decentraland Login\r\nEphemeral address: 0x4A1b9FD363dE915145008C41FA217377B2C223F2\r\nExpiration: 2123-03-18T16:59:36.515Z",
              "signature": "0x00050203596af90cecdbf9a768886e771178fd5561dd27ab005d000100019dde76f11e2c6aff01f6548f3046a9d0c569e13e79dec4218322068d3123e1162167fabd84dccfaabd350b93d2405f7b8a9cef4846b4d9a55d17838809a0e2591b020101c50adeadb7fe15bee45dcb820610cdedcd314eb0030102640dccefda3685e6c0dbeb70c1cf8018c27077eb00021cfbe892a1b29ac5e2fda1038c7965656be94aec57b658582f16447089bcf50b09df216a7e21d861cd7474723a7bfc70bf1caa55a962476cf78eb4b54471018b1b020103d9e87370ededc599df3bf9dd0e48586005f1a1bb"
            },
            {
              "type": "ECDSA_SIGNED_ENTITY",
              "payload": "QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo",
              "signature": "0xb962b57accc8e12083769339888f82752d13f280012b2c7b2aa2722eae103aea7a623dc88605bf7036ec8c23b0bb8f036b52f5e4e30ee913f6f2a077d5e5e3e01b"
            }
          ]"#).unwrap();

        let authenticator = Authenticator::new();
        let result = authenticator
            .verify_signature(&chain, "QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo")
            .await;

        assert_eq!(result, Err(AuthenticatorError::ValidationError {
            position: 1,
            kind: "ECDSA_EIP_1654_EPHEMERAL".to_string(),
            message: "rpc resolver not implemented".to_string()
        }));
    }

    #[tokio::test]
    async fn test_should_fail_if_ephemeral_is_expired() {
        let authenticator = Authenticator::new();
        let chain = AuthChain::from_json(r#"[
            {
              "type": "SIGNER",
              "payload": "0x84452bbfa4ca14b7828e2f3bbd106a2bd495cd34",
              "signature": ""
            },
            {
              "type": "ECDSA_EPHEMERAL",
              "payload": "Decentraland Login\nEphemeral address: 0xe94944439fAB988e5e14b128BbcF6D5502b05f9C\nExpiration: 2020-02-20T00:00:00.000Z",
              "signature": "0x2d45e2a3e9e04614cf6bb822951b849458a78037733202d4bda12e60ef1ff4d266b02af7b72caa232c45052520fd440869672da2b0966b29fff21638e3d21ca01b"
            },
            {
              "type": "ECDSA_SIGNED_ENTITY",
              "payload": "QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo",
              "signature": "0x6ae9bbd2af56ea61db3afe188d78381f0cb3177376b12537a3cb01e5d242c3fc49955475615209f194d98f0c751a24f712ab1c0caa9f92fa222bd2e13e2efd611c"
            }
          ]"#).unwrap();

        let result = authenticator
            .verify_signature(&chain, "QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo")
            .await;

        assert_eq!(
            result,
            Err(AuthenticatorError::ExpiredEntity {
                position: 1,
                kind: String::from("ECDSA_EPHEMERAL")
            })
        );

        let time = DateTime::parse_from_rfc3339("2020-01-01T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        let owner = authenticator
            .verify_signature_at(
                &chain,
                "QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo",
                &time,
            )
            .await
            .unwrap();

        let expected = &Address::try_from("0x84452bbfa4ca14b7828e2f3bbd106a2bd495cd34").unwrap();
        assert_eq!(owner, expected);
    }

    #[tokio::test]
    async fn test_should_recover_address_from_signature() {
        let account = Account::random();
        let payload = "QmWyFNeHbxXaPtUnzKvDZPpKSa4d5anZEZEFJ8TC1WgcfU";
        let signature = account.sign(payload);
        let authenticator = Authenticator::new();
        let result =
            authenticator.validate_personal(&account.address(), payload, &signature.to_vec());

        assert!(result.is_ok());
        assert!(result.unwrap());

        let chain = AuthChain::simple(account.address(), payload, signature.to_string()).unwrap();
        let owner = authenticator
            .verify_signature(&chain, payload)
            .await
            .unwrap();

        assert_eq!(owner, &account.address());
    }
}
