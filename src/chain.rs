use std::ops::Deref;
use serde::{Deserialize, Serialize};
use serde_json::Error as SerdeError;

use crate::account::{Address, EIP1271Signature, PersonalSignature, EphemeralPayload};


static SIGNER: &str = "SIGNER";
static ECDSA_EPHEMERAL: &str = "ECDSA_EPHEMERAL";
static ECDSA_SIGNED_ENTITY: &str = "ECDSA_SIGNED_ENTITY";
static ECDSA_EIP_1654_EPHEMERAL: &str = "ECDSA_EIP_1654_EPHEMERAL";
static ECDSA_EIP_1654_SIGNED_ENTITY: &str = "ECDSA_EIP_1654_SIGNED_ENTITY";

/// Representation of each link on an auth chain
///
/// ```rust
/// use decentraland_crypto::account::Address;
/// use decentraland_crypto::chain::AuthLink;
///
/// let signer = AuthLink::parse(r#"{"type": "SIGNER","payload": "0x3f17f1962b36e491b30a40b2405849e597ba5fb5","signature": ""}"#).unwrap();
/// let expected = AuthLink::Signer{ payload: Address::try_from("0x3f17f1962b36e491b30a40b2405849e597ba5fb5").unwrap(), signature: String::new() };
/// assert_eq!(signer, expected);
/// ```
///
/// ```rust
/// use decentraland_crypto::account::{Address, PersonalSignature, EphemeralPayload};
/// use decentraland_crypto::chain::AuthLink;
///
/// let personal_ephemeral = AuthLink::parse(r#"{"type":"ECDSA_EPHEMERAL","payload":"Decentraland Login\nEphemeral address: 0x612f2657CE738799056051aB09926cE806CcDa0E\nExpiration: 2023-05-02T23:06:21.135Z","signature":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c5"}"#).unwrap();
/// let expected = AuthLink::EcdsaPersonalEphemeral{
///     payload: EphemeralPayload::try_from("Decentraland Login\nEphemeral address: 0x612f2657CE738799056051aB09926cE806CcDa0E\nExpiration: 2023-05-02T23:06:21.135Z").unwrap(),
///     signature: PersonalSignature::try_from("0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c5").unwrap(),
/// };
/// assert_eq!(personal_ephemeral, expected);
/// ```
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
#[serde(tag = "type")]
pub enum AuthLink {
    #[serde(rename = "SIGNER")]
    Signer{
        payload: Address,
        signature: String,
    },

    #[serde(rename = "ECDSA_EPHEMERAL")]
    EcdsaPersonalEphemeral {
        payload: EphemeralPayload,
        signature: PersonalSignature,
    },

    #[serde(rename = "ECDSA_SIGNED_ENTITY")]
    EcdsaPersonalSignedEntity {
        payload: String,
        signature: PersonalSignature,
    },

    /// See https://github.com/ethereum/EIPs/issues/1654
    /// See https://eips.ethereum.org/EIPS/eip-1271
    #[serde(rename = "ECDSA_EIP_1654_EPHEMERAL")]
    EcdsaEip1654Ephemeral {
        payload: EphemeralPayload,
        signature: EIP1271Signature,
    },

    /// See https://github.com/ethereum/EIPs/issues/1654
    /// See https://eips.ethereum.org/EIPS/eip-1271
    #[serde(rename = "ECDSA_EIP_1654_SIGNED_ENTITY")]
    EcdsaEip1654SignedEntity {
        payload: String,
        signature: EIP1271Signature,
    },
}

impl AuthLink {
    pub fn kind(&self) -> &str {
        match self {
            AuthLink::Signer{ .. } => SIGNER,
            AuthLink::EcdsaPersonalEphemeral { .. } => ECDSA_EPHEMERAL,
            AuthLink::EcdsaPersonalSignedEntity { .. } => ECDSA_SIGNED_ENTITY,
            AuthLink::EcdsaEip1654Ephemeral { .. } => ECDSA_EIP_1654_EPHEMERAL,
            AuthLink::EcdsaEip1654SignedEntity { .. } => ECDSA_EIP_1654_SIGNED_ENTITY,
        }
    }

    pub fn parse(value: &str) -> Result<AuthLink, SerdeError> {
        serde_json::from_str::<AuthLink>(value)
    }

    pub fn signer(payload: Address) -> Self {
        AuthLink::Signer{ payload, signature: String::new() }
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
#[serde(transparent)]
pub struct AuthChain(Vec<AuthLink>);

impl Deref for AuthChain {
    type Target = Vec<AuthLink>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<AuthLink>> for AuthChain {
    fn from(links: Vec<AuthLink>) -> Self {
        AuthChain(links)
    }
}

impl AuthChain {

    pub fn simple(signer: Address, payload: String, signature: PersonalSignature) -> Self {
        AuthChain::from(vec![
            AuthLink::signer(signer),
            AuthLink::EcdsaPersonalSignedEntity { payload, signature }
        ])
    }

    /// Parse a json string into an AuthChain
    ///
    /// ```rust
    /// use decentraland_crypto::chain::AuthChain;
    ///
    /// let chain = AuthChain::parse(r#"[
    ///       {
    ///        "type": "SIGNER",
    ///        "payload": "0x3f17f1962b36e491b30a40b2405849e597ba5fb5",
    ///        "signature": ""
    ///      },
    ///      {
    ///        "type": "ECDSA_EPHEMERAL",
    ///        "payload": "Decentraland Login\nEphemeral address: 0x612f2657CE738799056051aB09926cE806CcDa0E\nExpiration: 2023-05-02T23:06:21.135Z",
    ///        "signature": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c5"
    ///      },
    ///      {
    ///        "type": "ECDSA_SIGNED_ENTITY",
    ///        "payload": "signed message",
    ///        "signature": "0x6168f285b5f905510de86c042c08fea79a66fff86abdf9ba4d374d0a6680ffc52ac251e36430a208d2369692797b3b049164b4b68d7519f50c8e5022e100837c1c"
    ///      }
    ///    ]"#).unwrap();
    /// ```
    pub fn parse(value: &str) -> Result<AuthChain, SerdeError> {
        serde_json::from_str::<AuthChain>(value)
    }

    pub fn parse_links(value: Vec<&str>) -> Result<AuthChain, SerdeError> {
        let links = value
            .iter()
            .map(|link| {
                let link = serde_json::from_str::<AuthLink>(link)?;
                Ok(link)
            })
            .collect::<Result<Vec<AuthLink>, SerdeError>>()?;

        Ok(AuthChain::from(links))
    }

    pub fn owner(&self) -> Option<&Address> {
        match (*self).first() {
            Some(AuthLink::Signer{ payload, .. }) => Some(payload),
            _ => None,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.iter().any(|link| match link {
            AuthLink::EcdsaPersonalEphemeral { payload, .. } => payload.is_expired(),
            AuthLink::EcdsaEip1654Ephemeral { payload, .. } => payload.is_expired(),
            _ => false,
        })
    }

    pub fn is_expired_at(&self, time: chrono::DateTime<chrono::Utc>) -> bool {
        self.iter().any(|link| match link {
            AuthLink::EcdsaPersonalEphemeral { payload, .. } => payload.is_expired_at(time),
            AuthLink::EcdsaEip1654Ephemeral { payload, .. } => payload.is_expired_at(time),
            _ => false,
        })
    }
}
