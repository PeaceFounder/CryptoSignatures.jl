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
#verify(data,hashnum::UInt64) = hash("$data")==hashnum
verify(data,hash) = errror("Must be implemented by hash type.")
verify(data,s::AbstractSignature,G::AbstractGroup) = verify(s,G) && verify(data,s.hash)

abstract type AbstractSigner end
#id(s::AbstractSigner) = s.pubkey

abstract type AbstractEncryptionKey end
abstract type AbstractDecryptionKey end

# The singer does store group to prevent the private key to be accidentally missused with different group which would lower the security. And the singature would be useless in such case.
struct Signer{T} <: AbstractSigner where T<:Integer
    privkey::T
    pubkey::T
    G::AbstractGroup
end

import Base.Dict
function Dict(signer::Signer)
    dict = Dict()
    dict["priv"] = string(signer.privkey,base=16)
    dict["pub"] = string(signer.pubkey,base=16)
    return dict
end

function Signer{BigInt}(dict::Dict,G::AbstractGroup)
    priv = parse(BigInt,dict["priv"],base=16)
    pub = parse(BigInt,dict["pub"],base=16)
    Signer(priv,pub,G)
end


function Signer(G::AbstractGroup;rng=rng())
    x = rand(1:order(G))
    y = value(G^x)
    Signer(x,y,G)
end

import Base.==
==(x::Signer,y::Signer) = x.privkey==y.privkey && x.pubkey==y.pubkey && x.G==y.G

### There are many different ways one could sing stuff. 
# include("rsasignatures.jl")
include("dsasignatures.jl")

export verify, Signer, DSASignature

end # module
