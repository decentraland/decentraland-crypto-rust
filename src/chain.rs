use std::ops::Deref;
use serde::{Deserialize, Serialize};
use serde_json::Error as SerdeError;

use crate::{account::{Address, EIP1271Signature, PersonalSignature, EphemeralPayload, PERSONAL_SIGNATURE_SIZE, DecodeHexError}};


static SIGNER: &str = "SIGNER";
static ECDSA_EPHEMERAL: &str = "ECDSA_EPHEMERAL";
static ECDSA_SIGNED_ENTITY: &str = "ECDSA_SIGNED_ENTITY";
static ECDSA_EIP_1654_EPHEMERAL: &str = "ECDSA_EIP_1654_EPHEMERAL";
static ECDSA_EIP_1654_SIGNED_ENTITY: &str = "ECDSA_EIP_1654_SIGNED_ENTITY";

/// Representation of each link on an auth chain
///
/// ```rust
/// use dcl_crypto::account::Address;
/// use dcl_crypto::chain::AuthLink;
///
/// let signer = AuthLink::parse(r#"{"type": "SIGNER","payload": "0x3f17f1962b36e491b30a40b2405849e597ba5fb5","signature": ""}"#).unwrap();
/// let expected = AuthLink::Signer{ payload: Address::try_from("0x3f17f1962b36e491b30a40b2405849e597ba5fb5").unwrap(), signature: String::new() };
/// assert_eq!(signer, expected);
/// ```
///
/// ```rust
/// use dcl_crypto::account::{Address, PersonalSignature, EphemeralPayload};
/// use dcl_crypto::chain::AuthLink;
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

    /// See <https://github.com/ethereum/EIPs/issues/1654>
    /// See <https://eips.ethereum.org/EIPS/eip-1271>
    #[serde(rename = "ECDSA_EIP_1654_EPHEMERAL")]
    EcdsaEip1654Ephemeral {
        payload: EphemeralPayload,
        signature: EIP1271Signature,
    },

    /// See <https://github.com/ethereum/EIPs/issues/1654>
    /// See <https://eips.ethereum.org/EIPS/eip-1271>
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


    /// Returns the original owner of the chain
    ///
    /// ```rust
    /// use dcl_crypto::chain::AuthChain;
    /// use dcl_crypto::account::Address;
    ///
    /// let address = Address::try_from("0x4A1b9FD363dE915145008C41FA217377B2C223F2").unwrap();
    /// let payload = "QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo";
    /// let signature = "0xb962b57accc8e12083769339888f82752d13f280012b2c7b2aa2722eae103aea7a623dc88605bf7036ec8c23b0bb8f036b52f5e4e30ee913f6f2a077d5e5e3e01b";
    ///
    /// let chain = AuthChain::simple(address, payload, signature).unwrap();
    /// let owner = chain.owner().unwrap();
    /// assert_eq!(owner, &Address::try_from("0x4A1b9FD363dE915145008C41FA217377B2C223F2").unwrap());
    /// ```
    ///
    /// ```rust
    /// use dcl_crypto::chain::AuthChain;
    /// use dcl_crypto::account::Address;
    ///
    /// let address = Address::try_from("0x8C889222833F961FC991B31d15e25738c6732930").unwrap();
    /// let payload = "QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo";
    /// let signature = "0x00050203596af90cecdbf9a768886e771178fd5561dd27ab005d000100018d7c77aaeb3a8529951423128fa5b807192c27c4ce5af76bbf73ffc84eecd48c4a004c4b4db03cf04b269ad0f1fcf26c31b859cb0a693eeb3b8efd89dc9e3bea1b020101c50adeadb7fe15bee45dcb820610cdedcd314eb0030102640dccefda3685e6c0dbeb70c1cf8018c27077eb00020af67e80c0f311fddd79d3163c8ee840863a5a1eb3d236b10b8b6972164164236b32e13443e3cfe1be591534cb93607cf6e49e48e51f012e806c158819fa7b471c020103d9e87370ededc599df3bf9dd0e48586005f1a1bb";
    ///
    /// let chain = AuthChain::simple(address, payload, signature).unwrap();
    /// let owner = chain.owner().unwrap();
    /// assert_eq!(owner, &Address::try_from("0x8C889222833F961FC991B31d15e25738c6732930").unwrap());
    /// ```
    pub fn simple<P, T>(signer: Address, payload: P, signature: T) -> Result<Self, DecodeHexError> where P: AsRef<str>, T: AsRef<str> {
        let signature = signature.as_ref();
        let payload = payload.as_ref().to_string();
        let entity = if signature.len() == (PERSONAL_SIGNATURE_SIZE * 2) + 2 {
            let signature = PersonalSignature::try_from(signature)?;
            AuthLink::EcdsaPersonalSignedEntity { payload, signature }
        } else {
            let signature = EIP1271Signature::try_from(signature)?;
            AuthLink::EcdsaEip1654SignedEntity { payload, signature }
        };

        Ok(AuthChain::from(vec![
            AuthLink::signer(signer),
            entity
        ]))
    }

    /// Parse a json string and returns an AuthChain
    ///
    /// ```rust
    /// use dcl_crypto::chain::AuthChain;
    /// use dcl_crypto::account::Address;
    ///
    /// let chain = AuthChain::from_json(r#"[
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
    ///
    /// let owner = chain.owner().unwrap();
    /// assert_eq!(owner, &Address::try_from("0x3f17f1962b36e491b30a40b2405849e597ba5fb5").unwrap());
    pub fn from_json<V>(value: V) -> Result<AuthChain, SerdeError> where V: AsRef<str> {
        serde_json::from_str::<AuthChain>(value.as_ref())
    }

    /// Parse a list of json strings and returns an AuthChain
    ///
    /// ```rust
    /// use dcl_crypto::account::Address;
    /// use dcl_crypto::chain::AuthChain;
    ///
    /// let chain = AuthChain::from_json_links(vec![
    ///      r#"{
    ///        "type": "SIGNER",
    ///        "payload": "0x3f17f1962b36e491b30a40b2405849e597ba5fb5",
    ///        "signature": ""
    ///      }"#,
    ///     r#"{
    ///        "type": "ECDSA_EPHEMERAL",
    ///        "payload": "Decentraland Login\nEphemeral address: 0x612f2657CE738799056051aB09926cE806CcDa0E\nExpiration: 2023-05-02T23:06:21.135Z",
    ///        "signature": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c5"
    ///      }"#,
    ///     r#"{
    ///        "type": "ECDSA_SIGNED_ENTITY",
    ///        "payload": "signed message",
    ///        "signature": "0x6168f285b5f905510de86c042c08fea79a66fff86abdf9ba4d374d0a6680ffc52ac251e36430a208d2369692797b3b049164b4b68d7519f50c8e5022e100837c1c"
    ///      }"#]).unwrap();
    ///
    /// let owner = chain.owner().unwrap();
    /// assert_eq!(owner, &Address::try_from("0x3f17f1962b36e491b30a40b2405849e597ba5fb5").unwrap());
    /// ```
    pub fn from_json_links(value: Vec<&str>) -> Result<AuthChain, SerdeError> {
        let links = value
            .iter()
            .map(|link| {
                let link = serde_json::from_str::<AuthLink>(link)?;
                Ok(link)
            })
            .collect::<Result<Vec<AuthLink>, SerdeError>>()?;

        Ok(AuthChain::from(links))
    }

    /// Returns the original owner of the chain
    ///
    /// ```rust
    /// use dcl_crypto::chain::AuthChain;
    /// use dcl_crypto::account::Address;
    ///
    /// let chain = AuthChain::from_json(r#"[
    ///     { "type": "SIGNER", "payload": "0x84452bbfa4ca14b7828e2f3bbd106a2bd495cd34", "signature": ""},
    ///     { "type": "ECDSA_SIGNED_ENTITY", "payload": "signed message", "signature": "0x013e0b0b75bd8404d70a37d96bb893596814d8f29f517e383d9d1421111f83c32d4ca0d6e399349c7badd54261feaa39895d027880d28d806c01089677400b7c1b"}
    /// ]"#).unwrap();
    ///
    /// let owner = chain.owner().unwrap();
    /// assert_eq!(owner, &Address::try_from("0x84452bbfa4ca14b7828e2f3bbd106a2bd495cd34").unwrap());
    /// ```
    pub fn owner(&self) -> Option<&Address> {
        match (*self).first() {
            Some(AuthLink::Signer{ payload, .. }) => Some(payload),
            _ => None,
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = &chrono::Utc::now();
        self.iter().any(|link| match link {
            AuthLink::EcdsaPersonalEphemeral { payload, .. } => payload.is_expired_at(now),
            AuthLink::EcdsaEip1654Ephemeral { payload, .. } => payload.is_expired_at(now),
            _ => false,
        })
    }

    pub fn is_expired_at(&self, time: &chrono::DateTime<chrono::Utc>) -> bool {
        self.iter().any(|link| match link {
            AuthLink::EcdsaPersonalEphemeral { payload, .. } => payload.is_expired_at(time),
            AuthLink::EcdsaEip1654Ephemeral { payload, .. } => payload.is_expired_at(time),
            _ => false,
        })
    }
}
