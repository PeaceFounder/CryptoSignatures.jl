module CryptoSignatures

### This is a meta package which wraps all known asymmetric cryptographic libraries in a consistent interface for performing this simple task of making signatures

# using ECC
# using Prallier

### One could also have a ring signatures. One might perhaps now look on them as a different abstarct type. On the other hand that perhaps could be hidden under the type of public keys withn the signature. 

struct Signature
    hash # hash could have its own type
    secret
    pubkey # in the same way as public key would have its own type
end

struct Signer
    privkey # encryption key
    pubkey # decryption key
end

Signer(keypair) = Signer(keypair...)
### One initiates signer with a simple
# Signer(Cryptomodule.generatekeypair()) 

verify(data,s::Signature) = decrypt(s.secret,s.pubkey)==s.hash.hash && verify(data,s.hash)

id(s::Signature) = s.pubkey ### One can overwrite this as one wishes
id(s::Signer) = s.pubkey

import Base.sign

function sign(data,hash,s::Signer)
    h = hash(data)
    return Signature(h,encrypt(h,s.privkey),s.pubkey)
end


### A temporary wrapper for Nettle. 

import Nettle

abstract type Hash end

function stringtoint(s::AbstractString)
    unitvec = collect(codeunits(s))

    s = BigInt(unitvec[1])
    for n in unitvec[2:end]
        s *= 256
        s += n
    end
    return s
end

struct SHA256 <: Hash
    hash
    function SHA256(data)
        h = Nettle.hexdigest("sha256","$data")
        new(stringtoint(h))
    end
end

verify(data,hash::Hash) = typeof(hash)(data).hash==hash.hash


### A temporary wrapper for Paillier. Fixing api. 

import Paillier

#generatekeypair(N) = Paillier.generate_paillier_keypair(N)
#generatesigner(N) = Signer(generatekeypair(N)...)

encrypt(data::Integer,priv::Paillier.PublicKey) = Paillier.encrypt(priv,data)
#encrypt(data::AbstractString,priv::Paillier.PublicKey) = Paillier.encrypt(priv,stringtoint(data))
encrypt(data::Hash,priv::Paillier.PublicKey) = encrypt(data.hash,priv)

decrypt(data,pub::Paillier.PrivateKey) = Paillier.decrypt(pub,data)


export verify, sign, id, Signer, Signature

### Theese should be nonexistant for this library
export SHA256

end # module
