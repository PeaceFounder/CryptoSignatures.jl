# TODO: implement RSA assymetric cryptography. (A sepperate package) https://en.wikipedia.org/wiki/RSA_(cryptosystem). 
# Also other systems like ElGammal, XTR could be implemented

struct RSASignature{H,P} <: AbstractSignature
    hash::H # hash could have its own type
    secret
    pubkey::P # in the same way as public key would have its own type
end

verify(s::RSASignature) = decrypt(s.secret,s.pubkey)==s.hash.hash

### For the system hash function which noone is supposed to use
verify(s::RSASignature{UInt64,P}) where P <: Any = decrypt(s.secret,s.pubkey)==s.hash

function rsasign(data,hash,s::Signer)
    h = hash(data)
    return RSASignature(h,encrypt(h,s.privkey),s.pubkey)
end

### An exception when one uses Paillier for the job. But with high probably this is shit.
import Paillier

encrypt(data::Integer,priv::Paillier.PublicKey) = Paillier.encrypt(priv,data)
#encrypt(data::Hash,priv::Paillier.PublicKey) = encrypt(data.hash,priv) # data.hash must be integer

decrypt(data,pub::Paillier.PrivateKey) = Paillier.decrypt(pub,data)



