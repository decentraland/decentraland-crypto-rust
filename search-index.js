var searchIndex = JSON.parse('{\
"decentraland_crypto":{"doc":"","t":[0,0,0,3,4,4,3,6,3,13,13,13,13,13,13,13,13,13,13,3,12,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,5,5,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,12,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,12,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,12,12,3,4,13,13,13,13,13,13,13,13,13,13,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,12,12,12,12,12,12,12,12,12,12,12,12,3,4,13,13,13,13,13,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,12,12,12,12,12,12,12,12,12,12],"n":["account","authenticator","chain","Address","DecodeHexError","DelegationPayloadError","EIP1271Signature","EIP1654Signature","EphemeralPayload","InvalidAddress","InvalidExpiration","InvalidHexCharacter","InvalidLength","InvalidPayload","MissingAddress","MissingExpiration","MissingPrefix","MissingTitle","OddLength","PersonalSignature","address","borrow","borrow","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","clone","clone","clone","clone","clone_into","clone_into","clone_into","clone_into","decode","decode_to_slice","default","default","deref","deref","deref","deserialize","deserialize","deserialize","deserialize","eq","eq","eq","eq","eq","eq","eq","eq","expiration","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","from","from","from","from","from","from","from","from","from","from","from","from","from","into","into","into","into","into","into","is_expired","is_expired_at","is_valid_signature","new","new_with_title","provide","provide","serialize","serialize","serialize","serialize","title","to_owned","to_owned","to_owned","to_owned","to_string","to_string","to_string","to_string","to_string","to_string","to_string_checksum","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","try_into","try_into","try_recover_from_message","type_id","type_id","type_id","type_id","type_id","type_id","vzip","vzip","vzip","vzip","vzip","vzip","zero","c","index","Authenticator","AuthenticatorError","EIP1654ValidatorNotImplemented","EmptyChain","EphemeralExpected","PersonalValidatorNotImplemented","SignedEntityExpected","SignedEntityMissing","SignerExpected","UnexpectedLastAuthority","UnexpectedSigner","ValidationError","borrow","borrow","borrow_mut","borrow_mut","default","fmt","fmt","from","from","from","from","into","into","provide","to_string","try_from","try_from","try_into","try_into","type_id","type_id","validate_personal","verify","vzip","vzip","with_eip1654_validator","expected","expected","found","found","found","found","found","position","position","position","position","position","AuthChain","AuthLink","EcdsaEip1654Ephemeral","EcdsaEip1654SignedEntity","EcdsaPersonalEphemeral","EcdsaPersonalSignedEntity","Signer","borrow","borrow","borrow_mut","borrow_mut","clone","clone","clone_into","clone_into","deref","deserialize","deserialize","eq","eq","fmt","fmt","from","from","from","into","into","is_expired","is_expired_at","kind","owner","parse","parse","parse_links","serialize","serialize","signer","simple","to_owned","to_owned","try_from","try_from","try_into","try_into","type_id","type_id","vzip","vzip","payload","payload","payload","payload","payload","signature","signature","signature","signature","signature"],"q":["decentraland_crypto","","","decentraland_crypto::account","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","decentraland_crypto::account::DecodeHexError","","decentraland_crypto::authenticator","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","decentraland_crypto::authenticator::AuthenticatorError","","","","","","","","","","","","decentraland_crypto::chain","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","decentraland_crypto::chain::AuthLink","","","","","","","","",""],"d":["","","","","An error that can occur when decoding a hexadecimal string","","And","Alias of EIP1271Signature See …","An <code>EphemeralPayload</code> is a message that delegates the right …","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","Decodes a hex string prefixed with <code>0x</code> into raw bytes.","Decode a hex string prefixed with <code>0x</code> into a mutable bytes …","","","","","","","","","","","","","","","","","","","","","","Formats the <code>Address</code> into its hexadecimal uppercase …","Formats the <code>Address</code> into its hexadecimal lowercase …","Format an Address into it string representation","","Format signature on its hexadecimal representation","","","","","","","Returns the argument unchanged.","","Returns the argument unchanged.","Converts an <code>H160</code> into an <code>Address</code>","Converts <code>[u8; 20]</code> into an <code>Address</code>","","","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","","Returns the argument unchanged.","","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","","","","","","","","","","","","","","","","","","","","","","","Calculate ERC-55 version of the address","","","Converts an hexadecimal representation into an Address","","","","","","","","","","","","","","","","","","Recover the signer of the signature from a giving message","","","","","","","","","","","","","Creates an instance of the zero address","","","Validates a message and has correspond to an address.","","","","","","","","","","","","","","","","","","","Returns the argument unchanged.","","","Returns the argument unchanged.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","","","","","","","","","Validates a message and has correspond to an address.","","","","","","","","","","","","","","","","","","Representation of each link on an auth chain","See https://github.com/ethereum/EIPs/issues/1654 See …","See https://github.com/ethereum/EIPs/issues/1654 See …","","","","","","","","","","","","","","","","","","","Returns the argument unchanged.","","Returns the argument unchanged.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","","","","","","Parse a json string into an AuthChain","","","","","","","","","","","","","","","","","","","","","","","","",""],"i":[0,0,0,0,0,0,0,0,0,12,12,8,8,12,12,12,8,12,8,0,4,8,1,2,3,4,12,8,1,2,3,4,12,1,2,3,4,1,2,3,4,0,0,1,2,1,2,3,1,2,3,4,8,1,1,1,2,3,4,12,4,8,8,1,1,1,1,2,2,3,3,4,4,12,12,8,8,1,1,1,2,2,2,3,4,12,12,12,8,1,2,3,4,12,4,4,2,4,4,8,12,1,2,3,4,4,1,2,3,4,8,1,2,3,4,12,1,8,1,1,1,2,2,2,3,3,3,4,4,4,12,8,1,2,3,4,12,2,8,1,2,3,4,12,8,1,2,3,4,12,1,31,31,0,0,25,25,25,25,25,25,25,25,25,25,25,24,25,24,24,25,25,25,25,25,24,25,24,25,25,25,24,25,24,25,24,24,24,25,24,24,32,33,34,35,36,32,33,34,35,36,32,33,0,0,28,28,28,28,28,28,27,28,27,28,27,28,27,27,28,27,28,27,28,27,28,27,27,28,27,27,27,28,27,28,27,27,28,27,28,27,28,27,28,27,28,27,28,27,28,27,37,38,39,40,41,37,38,39,40,41],"f":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[1,1],[2,2],[3,3],[4,4],[[]],[[]],[[]],[[]],[5,[[9,[[7,[6]],8]]]],[5,[[9,[8]]]],[[],1],[[],2],[1],[2],[3],[[],[[9,[1]]]],[[],[[9,[2]]]],[[],[[9,[3]]]],[[],[[9,[4]]]],[[8,8],10],[[1,11],10],[[1,11],10],[[1,1],10],[[2,2],10],[[3,3],10],[[4,4],10],[[12,12],10],0,[[8,13],14],[[8,13],14],[[1,13],14],[[1,13],14],[[1,13],14],[[1,13],14],[[2,13],14],[[2,13],14],[[3,13],14],[[3,13],14],[[4,13],14],[[4,13],14],[[12,13],14],[[12,13],14],[[]],[15,8],[[]],[11,1],[[],1],[[],2],[16,2],[[]],[[]],[[]],[8,12],[[]],[17,12],[[]],[[]],[[]],[[]],[[]],[[]],[4,10],[[4,[19,[18]]],10],[[2,5,1],10],[[1,[19,[18]]],4],[[20,1,[19,[18]]],4],[21],[21],[1,9],[2,9],[3,9],[4,9],0,[[]],[[]],[[]],[[]],[[],20],[[],20],[[],20],[[],20],[[],20],[[],20],[1,20],[[],9],[20,[[9,[1]]]],[5,[[9,[1]]]],[[],9],[[],9],[20,[[9,[2]]]],[5,[[9,[2]]]],[20,[[9,[3]]]],[[],9],[5,[[9,[3]]]],[[],9],[5,[[9,[4]]]],[20,[[9,[4]]]],[[],9],[[],9],[[],9],[[],9],[[],9],[[],9],[[],9],[[2,5],[[9,[1,22]]]],[[],23],[[],23],[[],23],[[],23],[[],23],[[],23],[[]],[[]],[[]],[[]],[[]],[[]],[[],1],0,0,0,0,0,0,0,0,0,0,0,0,0,0,[[]],[[]],[[]],[[]],[[],24],[[25,13],14],[[25,13],14],[[]],[26,25],[22,25],[[]],[[]],[[]],[21],[[],20],[[],9],[[],9],[[],9],[[],9],[[],23],[[],23],[[1,20,[7,[6]]],[[9,[10,25]]]],[[24,27,5],[[9,[1,25]]]],[[]],[[]],[24,24],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,[[]],[[]],[[]],[[]],[28,28],[27,27],[[]],[[]],[27],[[],[[9,[28]]]],[[],[[9,[27]]]],[[28,28],10],[[27,27],10],[[28,13],14],[[27,13],14],[[]],[[[7,[28]]],27],[[]],[[]],[[]],[27,10],[[27,[19,[18]]],10],[28,5],[27,[[29,[1]]]],[5,[[9,[28,30]]]],[5,[[9,[27,30]]]],[[[7,[5]]],[[9,[27,30]]]],[28,9],[27,9],[1,28],[[1,20,2],27],[[]],[[]],[[],9],[[],9],[[],9],[[],9],[[],23],[[],23],[[]],[[]],0,0,0,0,0,0,0,0,0,0],"p":[[3,"Address"],[3,"PersonalSignature"],[3,"EIP1271Signature"],[3,"EphemeralPayload"],[15,"str"],[15,"u8"],[3,"Vec"],[4,"DecodeHexError"],[4,"Result"],[15,"bool"],[3,"H160"],[4,"DelegationPayloadError"],[3,"Formatter"],[6,"Result"],[4,"FromHexError"],[3,"Signature"],[3,"ParseError"],[3,"Utc"],[3,"DateTime"],[3,"String"],[3,"Demand"],[4,"RecoveryError"],[3,"TypeId"],[3,"Authenticator"],[4,"AuthenticatorError"],[4,"Error"],[3,"AuthChain"],[4,"AuthLink"],[4,"Option"],[3,"Error"],[13,"InvalidHexCharacter"],[13,"UnexpectedSigner"],[13,"UnexpectedLastAuthority"],[13,"SignerExpected"],[13,"EphemeralExpected"],[13,"SignedEntityExpected"],[13,"Signer"],[13,"EcdsaPersonalEphemeral"],[13,"EcdsaPersonalSignedEntity"],[13,"EcdsaEip1654Ephemeral"],[13,"EcdsaEip1654SignedEntity"]]}\
}');
if (typeof window !== 'undefined' && window.initSearch) {window.initSearch(searchIndex)};
if (typeof exports !== 'undefined') {exports.searchIndex = searchIndex};
