use serde::{Serialize, Deserialize};
use crate::account::{Account, Expiration};
use crate::chain::AuthChain;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    ephemeral_identity: Account,
    auth_chain: AuthChain,
    expiration: Expiration,
}
