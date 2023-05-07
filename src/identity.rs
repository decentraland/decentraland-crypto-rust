use serde::{Serialize, Deserialize};
use crate::AuthLink;
use crate::account::{Account, Expiration, Signer, EphemeralPayload};

#[derive(Debug, Clone, Serialize, Deserialize)]
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

}
