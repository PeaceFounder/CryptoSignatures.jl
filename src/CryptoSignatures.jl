module CryptoSignatures

abstract type AbstractSignature end

id(s::AbstractSignature) = s.pubkey ### One can overwrite this as one wishes

"""
Never use this for deployed application!!!
"""
verify(data,hashnum::UInt64) = hash(data)==hashnum
verify(data,s::AbstractSignature) = verify(s) && verify(data,s.hash)

abstract type AbstractSigner end
id(s::AbstractSigner) = s.pubkey

struct Signer <: AbstractSigner
    privkey # encryption key
    pubkey # decryption key
end

Signer(keypair) = Signer(keypair...)

### There are many different ways one could sing stuff. 
##### rsasign, dsasign, ringsign 

include("rsasignatures.jl")

export verify, rsasign, id, Signer, Signature

end # module
