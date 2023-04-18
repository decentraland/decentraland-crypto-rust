use std::{time::Instant};

use web3::{
    types::{H256, H512},
};

use crate::{account::Address, chain::AuthChain};

pub type PublicKey = H512;
pub type PrivateKey = H256;

pub struct EphemeralIdentity {
    pub address: Address,
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

pub struct Identity {
    ephemeral_identity: EphemeralIdentity,
    auth_chain: AuthChain,
    expiration: Instant,
}
