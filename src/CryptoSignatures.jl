module CryptoSignatures

using CryptoGroups
using Random 

rng() = RandomDevice()

# const _default_rng = Ref{RandomDevice}()
# function __init__()
#     _default_rng[] = RandomDevice()
# end

# default_rng() = _default_rng[]

abstract type AbstractSignature end

id(s::AbstractSignature) = s.pubkey ### One can overwrite this as one wishes

"""
Never use this for deployed application!!!
"""
verify(data,hashnum::UInt64) = hash(data)==hashnum
verify(data,s::AbstractSignature,G::AbstractGroup) = verify(s,G) && verify(data,s.hash)

abstract type AbstractSigner end
id(s::AbstractSigner) = s.pubkey

abstract type AbstractEncryptionKey end
abstract type AbstractDecryptionKey end

# The singer does store group to prevent the private key to be accidentally missused with different group which would lower the security. And the singature would be useless in such case.
struct Signer{K,P} <: AbstractSigner
    privkey::K
    pubkey::P
    G::AbstractGroup
end

function Signer(G::AbstractGroup;rng=rng())
    x = rand(1:order(G))
    y = binary(G^x)
    Signer(x,y,G)
end

### There are many different ways one could sing stuff. 
# include("rsasignatures.jl")
include("dsasignatures.jl")

export verify, rsasign, id, Signer, DSASignature

end # module
