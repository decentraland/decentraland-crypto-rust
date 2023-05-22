use serde::{Serialize, Deserialize};
use crate::{AuthLink, AuthChain};
use crate::account::{Account, Expiration, Signer, EphemeralPayload, PersonalSignature};

/// An `Identity` is an abstraction where an Account that you don't control delegates the
/// ability to sign messages to a new address (encapsulated in the `Identity`) for a limited
/// amount of time using a signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    ephemeral_identity: Account,
    expiration: Expiration,
    auth_chain: Vec<AuthLink>,
}

/// Implements `Signer` trait for `Identity`
impl Signer for Identity {

    /// Returns the address of the ephemeral identity
    fn address(&self) -> crate::Address {
        self.ephemeral_identity.address()
    }

    /// Signs the given message with the ephemeral identity
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

    /// Creates a new Identity from the given Signer
    ///
    /// ```rust
    /// use dcl_crypto::{Identity, Account, Signer, Expiration};
    ///
    /// let signer = Account::random();
    /// let identity = Identity::from_signer(&signer, Expiration::try_from("3021-10-16T22:32:29.626Z").unwrap());
    /// let chain = identity.sign_payload("Hello World");
    ///
    /// assert_eq!(chain.owner(), Some(&signer.address()));
    /// assert_eq!(chain.len(), 3);
    /// ```
    pub fn from_signer<S: Signer, E: Into<Expiration>>(signer: &S, exp: E) -> Self {
        let ephemeral_identity = Account::random();
        let expiration = exp.into();

        let payload = EphemeralPayload::new(ephemeral_identity.address(), expiration);
        let signature = signer.sign(payload.to_string());

        Self {
            ephemeral_identity,
            expiration,
            auth_chain: vec![
                AuthLink::signer(signer.address()),
                AuthLink::EcdsaPersonalEphemeral{ payload, signature }
            ],
        }
    }

    /// Creates a new Identity extended from a given Identity
    ///
    /// ```rust
    /// use dcl_crypto::{Identity, Account, Signer, Expiration};
    ///
    /// let signer = Account::random();
    /// let identity1 = Identity::from_signer(&signer, Expiration::try_from("3021-10-16T22:32:29.626Z").unwrap());
    /// let identity2 = Identity::from_identity(&identity1, Expiration::try_from("3021-10-16T22:32:29.626Z").unwrap());
    /// let chain = identity2.sign_payload("Hello World");
    ///
    /// assert_eq!(chain.owner(), Some(&signer.address()));
    /// assert_eq!(chain.len(), 4);
    /// ```
    pub fn from_identity<E: Into<Expiration>>(identity: &Identity, exp: E) -> Self {
        let ephemeral_identity = Account::random();
        let mut expiration = exp.into();
        if identity.expiration < expiration {
            expiration = identity.expiration;
        }

        let payload = EphemeralPayload::new(ephemeral_identity.address(), expiration);
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
    ///  }"#).unwrap();
    ///
    /// assert_eq!(
    ///     identity.create_signature("Hello World!").to_string(),
    ///     "0x33e6b0f71b69d9dca7e25fa279cd70e2e9a44d0c11ab973a936a5b67ba3dbb6554ec2ea5cb4112b2f051dd95b47874c40b8bb7443a0bc4f16c67e2017e0dcb0c1c"
    /// );
    /// ```
    pub fn create_signature<M: AsRef<str>>(&self, payload: M) -> PersonalSignature {
        self.ephemeral_identity.sign(payload.as_ref())
    }

    /// Creates an AuthChain signing the the given payload
    ///
    /// ```rust
    /// use dcl_crypto::{Identity, Authenticator, Signer, Account, Expiration};
    ///
    /// # tokio_test::block_on(async {
    ///     let signer = Account::random();
    ///     let identity = Identity::from_signer(&signer, Expiration::try_from("3021-10-16T22:32:29.626Z").unwrap());
    ///     let chain = identity.sign_payload("Hello World!");
    ///     let address = Authenticator::new().verify_signature(&chain, "Hello World!").await.unwrap();
    ///     assert_eq!(address, &signer.address());
    /// })
    /// ```
    ///
    /// ```rust
    /// use dcl_crypto::{Identity, Authenticator, Signer, AuthChain};
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
    ///  }"#).unwrap();
    ///
    ///
    /// # tokio_test::block_on(async {
    ///     let chain = identity.sign_payload("Hello World!");
    ///     let address = Authenticator::new().verify_signature(&chain, "Hello World!").await.unwrap();
    ///     assert_eq!(identity.address().to_string(), "0x84452bbfa4ca14b7828e2f3bbd106a2bd495cd34");
    ///     assert_eq!(address.to_string(), "0x7949f9f239d1a0816ce5eb364a1f588ae9cc1bf5");
    ///     assert_eq!(
    ///         chain,
    ///         AuthChain::from_json(r#"[
    ///             {
    ///               "type": "SIGNER",
    ///               "payload": "0x7949f9f239d1a0816ce5eb364a1f588ae9cc1bf5",
    ///               "signature": ""
    ///             },
    ///             {
    ///               "type": "ECDSA_EPHEMERAL",
    ///               "payload": "Decentraland Login\nEphemeral address: 0x84452bbFA4ca14B7828e2F3BBd106A2bD495CD34\nExpiration: 3021-10-16T22:32:29.626Z",
    ///               "signature": "0x39dd4ddf131ad2435d56c81c994c4417daef5cf5998258027ef8a1401470876a1365a6b79810dc0c4a2e9352befb63a9e4701d67b38007d83ffc4cd2b7a38ad51b"
    ///             },
    ///             {
    ///               "type": "ECDSA_SIGNED_ENTITY",
    ///               "payload": "Hello World!",
    ///               "signature": "0x33e6b0f71b69d9dca7e25fa279cd70e2e9a44d0c11ab973a936a5b67ba3dbb6554ec2ea5cb4112b2f051dd95b47874c40b8bb7443a0bc4f16c67e2017e0dcb0c1c"
    ///             }
    ///         ]"#).unwrap()
    ///     );
    /// })
    /// ```
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
