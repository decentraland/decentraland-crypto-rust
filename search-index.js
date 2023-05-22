var searchIndex = JSON.parse('{\
"dcl_crypto":{"doc":"This crate is a port of the original <code>@dcl/crypto</code> …","t":"CCCCCCCCAAAAADDEDGDEDNNNNNNNNNNRDIKLMLLLLLLLLLLLLLLLLLLLLLLLLLLLLLFFLLLLLLLLLLLLLLLLLLLLLLLMLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLKLMLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLMMMMMMDENNNNNNNNNDLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLMMMMMMMMMMMMMMMMMDENNNNNLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLMMMMMMMMMMDLLLLLLLLLLLLLLLLLLLLLNNNNELLLLLLLFLLLLL","n":["Account","Address","AuthChain","AuthLink","Authenticator","Expiration","Identity","Signer","account","authenticator","chain","identity","util","Account","Address","DecodeHexError","EIP1271Signature","EIP1654Signature","EphemeralPayload","EphemeralPayloadError","Expiration","InvalidAddress","InvalidExpiration","InvalidHexCharacter","InvalidLength","InvalidPayload","MissingAddress","MissingExpiration","MissingPrefix","MissingTitle","OddLength","PERSONAL_SIGNATURE_SIZE","PersonalSignature","Signer","address","address","address","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","checksum","clone","clone","clone","clone","clone","clone","clone_into","clone_into","clone_into","clone_into","clone_into","clone_into","decode","decode_to_slice","default","default","deref","deref","deref","deref","deserialize","deserialize","deserialize","deserialize","deserialize","deserialize","eq","eq","eq","eq","eq","eq","eq","eq","eq","eq","equivalent","expiration","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","from","from","from","from","from","from","from","from","from","from","from","from","from","from","from","from","from_rng","into","into","into","into","into","into","into","into","is_expired","is_expired_at","is_valid_signature","new","new_with_title","partial_cmp","provide","provide","random","serialize","serialize","serialize","serialize","serialize","serialize","sign","sign","title","to_owned","to_owned","to_owned","to_owned","to_owned","to_owned","to_string","to_string","to_string","to_string","to_string","to_string","to_string","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_recover_from_message","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","vzip","vzip","vzip","vzip","vzip","vzip","vzip","vzip","zero","c","index","err","err","value","value","Authenticator","AuthenticatorError","EmptyChain","EphemeralExpected","ExpiredEntity","SignedEntityExpected","SignedEntityMissing","SignerExpected","UnexpectedLastAuthority","UnexpectedSigner","ValidationError","WithoutTransport","add_transport","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","clone","clone_into","create_signature","eq","fmt","fmt","fmt","from","from","from","into","into","into","new","prepare","provide","send","sign_payload","to_owned","to_string","try_from","try_from","try_from","try_into","try_into","try_into","type_id","type_id","type_id","validate_personal","verify_signature","verify_signature_at","vzip","vzip","vzip","with_transport","expected","expected","found","found","found","found","found","kind","kind","message","position","position","position","position","position","position","position","AuthChain","AuthLink","EcdsaEip1654Ephemeral","EcdsaEip1654SignedEntity","EcdsaPersonalEphemeral","EcdsaPersonalSignedEntity","Signer","borrow","borrow","borrow_mut","borrow_mut","clone","clone","clone_into","clone_into","deref","deserialize","deserialize","eq","eq","fmt","fmt","from","from","from","from_json","from_json_links","into","into","is_expired","is_expired_at","kind","owner","parse","serialize","serialize","signer","simple","to_owned","to_owned","try_from","try_from","try_into","try_into","type_id","type_id","vzip","vzip","payload","payload","payload","payload","payload","signature","signature","signature","signature","signature","Identity","address","borrow","borrow_mut","clone","clone_into","create_signature","deserialize","fmt","from","from_identity","from_json","from_signer","into","serialize","sign","sign_payload","to_owned","try_from","try_into","type_id","vzip","Call","Decode","Encode","NotImplemented","RPCCallError","borrow","borrow_mut","fmt","fmt","from","into","provide","rpc_call_is_valid_signature","to_string","try_from","try_into","type_id","vzip"],"q":["dcl_crypto","","","","","","","","","","","","","dcl_crypto::account","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","dcl_crypto::account::DecodeHexError","","dcl_crypto::account::EphemeralPayloadError","","","","dcl_crypto::authenticator","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","dcl_crypto::authenticator::AuthenticatorError","","","","","","","","","","","","","","","","","dcl_crypto::chain","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","dcl_crypto::chain::AuthLink","","","","","","","","","","dcl_crypto::identity","","","","","","","","","","","","","","","","","","","","","","dcl_crypto::util","","","","","","","","","","","","","","","","",""],"d":["","","","","","","","","","","","","","A Struct that allows us to sign messages and serialize and …","","An error that can occur when decoding a hexadecimal string","And","Alias of EIP1271Signature See …","An <code>EphemeralPayload</code> is a message that delegates the right …","","","","","","","","","","","","","","","A trait for signing messages with an associated address.","Return the address of the signer.","Return the address of the account.","","","","","","","","","","","","","","","","","","Calculate ERC-55 version of the address","","","","","","","","","","","","","Decodes a hex string prefixed with <code>0x</code> into raw bytes.","Decode a hex string prefixed with <code>0x</code> into a mutable bytes …","","","","","","","","","","","","","","","","","","","","","","","","","","","Format an Address into it string representation","Formats the <code>Address</code> into its hexadecimal lowercase …","","Formats the <code>Address</code> into its hexadecimal uppercase …","","Format signature on its hexadecimal representation","","","","","","","","","","Returns the argument unchanged.","","","Converts an <code>H160</code> into an <code>Address</code>","Converts <code>[u8; 20]</code> into an <code>Address</code>","Returns the argument unchanged.","","","","Returns the argument unchanged.","Returns the argument unchanged.","","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Creates a new account using a custom RNG (Random Number …","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","","","","","","","","","Creates a new account generating a random private key.","","","","","","","Sign a message with the Address’s private key.","Sign a message with the account.","","","","","","","","","","","","","","","","","","Converts an hexadecimal representation into an Address","","","","","","","","","","","","","","Creates a new account from a private key in hex format.","","","","","","","","","","","Recover the signer of the signature from a giving message","","","","","","","","","","","","","","","","","Creates an instance of the zero address","","","","","","","Validates a message and has correspond to an address.","","","","","","","","","","","","","","","","","","","","","Creates a personal signature from a given identity and …","","","","","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","","","","","Creates an authchain from a given identity and payload. …","","","","","","","","","","","","Validates a message and has correspond to an address.","Verifies and authchain is valid, not expired and …","Verifies and authchain is valid, not expired at a given …","","","","","","","","","","","","","","","","","","","","","","","Representation of each link on an auth chain","See https://github.com/ethereum/EIPs/issues/1654 See …","See https://github.com/ethereum/EIPs/issues/1654 See …","","","","","","","","","","","","","","","","","","","Returns the argument unchanged.","Returns the argument unchanged.","","Parse a json string and returns an AuthChain","Parse a list of json strings and returns an AuthChain","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","","","","Returns the original owner of the chain","","","","","Returns the original owner of the chain","","","","","","","","","","","","","","","","","","","","","An <code>Identity</code> is and abstraction where an Account that you …","Returns the address of the ephemeral identity","","","","","Creates a PersonalSignature for the given payload","","","Returns the argument unchanged.","Creates a new Identity extended from a given Identity","Creates a new Identity from the given JSON","Creates a new Identity from the given Signer","Calls <code>U::from(self)</code>.","","Signs the given message with the ephemeral identity","Creates an AuthChain signing the the given payload","","","","","","","","","","","","","","","Returns the argument unchanged.","Calls <code>U::from(self)</code>.","","A signature validator that receives an address, a message …","","","","",""],"i":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,15,15,11,11,15,15,15,11,15,11,0,0,0,44,2,7,11,1,4,5,6,15,7,2,11,1,4,5,6,15,7,2,1,1,4,5,6,7,2,1,4,5,6,7,2,0,0,1,4,1,4,5,6,1,4,5,6,7,2,11,1,1,1,4,5,6,15,7,2,2,7,11,11,1,1,1,1,4,4,5,5,6,6,15,15,7,7,2,11,11,11,1,1,1,4,4,4,4,5,6,6,15,7,2,2,11,1,4,5,6,15,7,2,7,7,4,7,7,6,11,15,2,1,4,5,6,7,2,44,2,7,1,4,5,6,7,2,11,1,4,5,6,15,7,11,1,1,1,4,4,4,5,5,5,6,6,6,15,7,7,7,2,2,2,11,1,4,5,6,15,7,2,4,11,1,4,5,6,15,7,2,11,1,4,5,6,15,7,2,1,45,45,46,47,46,47,0,0,34,34,34,34,34,34,34,34,34,0,31,31,34,30,31,34,30,30,30,31,34,34,34,30,31,34,30,31,34,30,31,30,34,30,31,30,34,31,34,30,31,34,30,31,34,30,31,31,31,31,34,30,31,48,49,50,51,52,48,49,53,54,53,50,51,52,53,48,49,54,0,0,39,39,39,39,39,39,38,39,38,39,38,39,38,38,39,38,39,38,39,38,39,38,38,38,38,39,38,38,38,39,38,39,39,38,39,38,39,38,39,38,39,38,39,38,39,38,55,56,57,58,59,55,56,57,58,59,0,33,33,33,33,33,33,33,33,33,33,33,33,33,33,33,33,33,33,33,33,33,42,42,42,42,0,42,42,42,42,42,42,42,0,42,42,42,42,42],"f":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,[[],1],[2,1],0,[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[1,3],[1,1],[4,4],[5,5],[6,6],[7,7],[2,2],[[]],[[]],[[]],[[]],[[]],[[]],[8,[[12,[[10,[9]],11]]]],[8,[[12,[11]]]],[[],1],[[],4],[1],[4],[5],[6],[[],[[12,[1]]]],[[],[[12,[4]]]],[[],[[12,[5]]]],[[],[[12,[6]]]],[[],[[12,[7]]]],[[],[[12,[2]]]],[[11,11],13],[[1,14],13],[[1,1],13],[[1,14],13],[[4,4],13],[[5,5],13],[[6,6],13],[[15,15],13],[[7,7],13],[[2,2],13],[[],13],0,[[11,16],17],[[11,16],17],[[1,16],17],[[1,16],17],[[1,16],17],[[1,16],17],[[4,16],17],[[4,16],17],[[5,16],17],[[5,16],17],[[6,16],17],[[6,16],17],[[15,16],17],[[15,16],17],[[7,16],17],[[7,16],17],[[2,16],17],[[]],[18,11],[19,11],[14,1],[[],1],[[]],[20,4],[21,4],[[],4],[[]],[[]],[[[23,[22]]],6],[[]],[[]],[[]],[[]],[[],2],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[7,13],[[7,23],13],[[4,8,1],13],[[1,6],7],[[3,1,6],7],[[6,6],[[25,[24]]]],[26],[26],[[],2],[1,12],[4,12],[5,12],[6,12],[7,12],[2,12],[27,4],[[2,27],4],0,[[]],[[]],[[]],[[]],[[]],[[]],[[],3],[[],3],[[],3],[[],3],[[],3],[[],3],[[],3],[[],12],[3,[[12,[1]]]],[[],12],[8,[[12,[1]]]],[8,[[12,[4]]]],[[],12],[3,[[12,[4]]]],[[],12],[3,[[12,[5]]]],[8,[[12,[5]]]],[[],12],[3,[[12,[6]]]],[8,[[12,[6]]]],[[],12],[3,[[12,[7]]]],[[],12],[8,[[12,[7]]]],[8,[[12,[2]]]],[3,[[12,[2]]]],[[],12],[[],12],[[],12],[[],12],[[],12],[[],12],[[],12],[[],12],[[],12],[[4,8],[[12,[1,28]]]],[[],29],[[],29],[[],29],[[],29],[[],29],[[],29],[[],29],[[],29],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[],1],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,[[[31,[30]],32],[[31,[32]]]],[[]],[[]],[[]],[[]],[[]],[[]],[30,30],[[]],[[[31,[32]],33,[27,[8]]],4],[[34,34],13],[[34,16],17],[[34,16],17],[[30,16],17],[[]],[[]],[[]],[[]],[[]],[[]],[[],[[31,[30]]]],[[30,8,[10,[35]]]],[26],[[30,36,37]],[[[31,[32]],33,[27,[8]]],38],[[]],[[],3],[[],12],[[],12],[[],12],[[],12],[[],12],[[],12],[[],29],[[],29],[[],29],[[[31,[32]],1,27],[[12,[13,28]]]],[[[31,[32]],38,8],[[12,[1,34]]]],[[[31,[32]],38,8,23],[[12,[1,34]]]],[[]],[[]],[[]],[32,[[31,[32]]]],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,[[]],[[]],[[]],[[]],[39,39],[38,38],[[]],[[]],[38],[[],[[12,[39]]]],[[],[[12,[38]]]],[[39,39],13],[[38,38],13],[[39,16],17],[[38,16],17],[[]],[[]],[[[10,[39]]],38],[[],[[12,[38,40]]]],[[[10,[8]]],[[12,[38,40]]]],[[]],[[]],[38,13],[[38,23],13],[39,8],[38,[[25,[1]]]],[8,[[12,[39,40]]]],[39,12],[38,12],[1,39],[1,[[12,[38,11]]]],[[]],[[]],[[],12],[[],12],[[],12],[[],12],[[],29],[[],29],[[]],[[]],0,0,0,0,0,0,0,0,0,0,0,[33,1],[[]],[[]],[33,33],[[]],[[33,[27,[8]]],4],[[],[[12,[33]]]],[[33,16],17],[[]],[[33,[41,[6]]],33],[[[27,[8]]],[[12,[33,40]]]],[[[41,[6]]],33],[[]],[33,12],[[33,27],4],[[33,[27,[8]]],38],[[]],[[],12],[[],12],[[],29],[[]],0,0,0,0,0,[[]],[[]],[[42,16],17],[[42,16],17],[[]],[[]],[26],[[43,1,3,[10,[9]]],[[12,[13,42]]]],[[],3],[[],12],[[],12],[[],29],[[]]],"p":[[3,"Address"],[3,"Account"],[3,"String"],[3,"PersonalSignature"],[3,"EIP1271Signature"],[3,"Expiration"],[3,"EphemeralPayload"],[15,"str"],[15,"u8"],[3,"Vec"],[4,"DecodeHexError"],[4,"Result"],[15,"bool"],[3,"H160"],[4,"EphemeralPayloadError"],[3,"Formatter"],[6,"Result"],[4,"Error"],[4,"FromHexError"],[3,"RecoverableSignature"],[3,"Signature"],[8,"TimeZone"],[3,"DateTime"],[4,"Ordering"],[4,"Option"],[3,"Demand"],[8,"AsRef"],[4,"RecoveryError"],[3,"TypeId"],[3,"WithoutTransport"],[3,"Authenticator"],[8,"Transport"],[3,"Identity"],[4,"AuthenticatorError"],[4,"Value"],[6,"RequestId"],[4,"Call"],[3,"AuthChain"],[4,"AuthLink"],[3,"Error"],[8,"Into"],[4,"RPCCallError"],[3,"Eth"],[8,"Signer"],[13,"InvalidHexCharacter"],[13,"InvalidAddress"],[13,"InvalidExpiration"],[13,"UnexpectedSigner"],[13,"UnexpectedLastAuthority"],[13,"SignerExpected"],[13,"EphemeralExpected"],[13,"SignedEntityExpected"],[13,"ValidationError"],[13,"ExpiredEntity"],[13,"Signer"],[13,"EcdsaPersonalEphemeral"],[13,"EcdsaPersonalSignedEntity"],[13,"EcdsaEip1654Ephemeral"],[13,"EcdsaEip1654SignedEntity"]]}\
}');
if (typeof window !== 'undefined' && window.initSearch) {window.initSearch(searchIndex)};
if (typeof exports !== 'undefined') {exports.searchIndex = searchIndex};
