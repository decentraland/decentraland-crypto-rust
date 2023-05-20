use serde::{Serialize, Deserialize};
use crate::{AuthLink, AuthChain};
use crate::account::{Account, Expiration, Signer, EphemeralPayload, PersonalSignature};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    ephemeral_identity: Account,
    expiration: Expiration,
    auth_chain: Vec<AuthLink>,
}

impl Signer for Identity {
    fn address(&self) -> crate::Address {
        self.ephemeral_identity.address()
    }

    fn sign<M: AsRef<[u8]>>(&self, message: M) -> crate::account::PersonalSignature {
        self.ephemeral_identity.sign(message)
    }
}

impl Identity {

    /// Creates a new Identity from the given JSON
    ///
    /// ```rust
    /// use dcl_crypto::Identity;
    ///
    /// let identity = Identity::from_json(r#"{
    ///   "ephemeralIdentity": {
    ///     "address": "0x84452bbFA4ca14B7828e2F3BBd106A2bD495CD34",
    ///     "publicKey": "0x0420c548d960b06dac035d1daf826472eded46b8b9d123294f1199c56fa235c89f2515158b1e3be0874bfb15b42d1551db8c276787a654d0b8d7b4d4356e70fe42",
    ///     "privateKey": "0xbc453a92d9baeb3d10294cbc1d48ef6738f718fd31b4eb8085efe7b311299399"
    ///   },
    ///   "expiration": "3021-10-16T22:32:29.626Z",
    ///   "authChain": [
    ///     {
    ///       "type": "SIGNER",
    ///       "payload": "0x7949f9f239d1a0816ce5eb364a1f588ae9cc1bf5",
    ///       "signature": ""
    ///     },
    ///     {
    ///       "type": "ECDSA_EPHEMERAL",
    ///       "payload": "Decentraland Login\nEphemeral address: 0x84452bbFA4ca14B7828e2F3BBd106A2bD495CD34\nExpiration: 3021-10-16T22:32:29.626Z",
    ///       "signature": "0x39dd4ddf131ad2435d56c81c994c4417daef5cf5998258027ef8a1401470876a1365a6b79810dc0c4a2e9352befb63a9e4701d67b38007d83ffc4cd2b7a38ad51b"
    ///     }
    ///   ]
    ///  }"#);
    ///
    /// assert!(identity.is_ok());
    /// ```
    pub fn from_json<J: AsRef<str>>(json: J) -> Result<Self, serde_json::Error> {
        serde_json::from_str::<Identity>(json.as_ref())
    }

    pub fn from_signer<S: Signer, E: Into<Expiration>>(signer: S, exp: E) -> Self {
        let ephemeral_identity = Account::random();
        let expiration = exp.into();
        let address = signer.address();

        let payload = EphemeralPayload::new(address, expiration);
        let signature = signer.sign(payload.to_string());

        Self {
            ephemeral_identity,
            expiration,
            auth_chain: vec![
                AuthLink::signer(address),
                AuthLink::EcdsaPersonalEphemeral{ payload, signature }
            ],
        }
    }

    pub fn from_identity<E: Into<Expiration>>(identity: &Identity, exp: E) -> Self {
        let ephemeral_identity = Account::random();
        let address = identity.address();
        let mut expiration = exp.into();
        if identity.expiration < expiration {
            expiration = identity.expiration;
        }

        let payload = EphemeralPayload::new(address, expiration);
        let signature = identity.sign(payload.to_string());
        let mut auth_chain: Vec<AuthLink> = identity.auth_chain.clone();
        auth_chain.push(AuthLink::EcdsaPersonalEphemeral{ payload, signature });

        Self {
            ephemeral_identity,
            expiration,
            auth_chain
        }
    }

    /// Creates a PersonalSignature for the given payload
    pub fn create_signature<M: AsRef<str>>(&self, payload: M) -> PersonalSignature {
        self.ephemeral_identity.sign(payload.as_ref())
    }

    /// Creates an AuthChain signing the the given payload
    pub fn sign_payload<M: AsRef<str>>(&self, payload: M) -> AuthChain {
        let entity = AuthLink::EcdsaPersonalSignedEntity {
            payload: payload.as_ref().to_string(),
            signature: self.create_signature(payload.as_ref())
        };

        let mut links = self.auth_chain.clone();
        links.push(entity);
        AuthChain::from(links)
    }

}
