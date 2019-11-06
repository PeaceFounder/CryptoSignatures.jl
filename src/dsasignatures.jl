struct DSASignature{H,P} <: AbstractSignature
    hash::H # hash could have its own type
    r 
    s
    pubkey::P #
end

import Base.mod
mod(G::CyclicGroup) = mod(value(G),order(G))
mod(n::Integer,G::CyclicGroup) = mod(n,order(G))

modinv(k::Integer,G::CyclicGroup) = powermod(k,order(G)-2,order(G))

function DSASignature(hash,signer::AbstractSigner,G::CyclicGroup)

    h = Integer(hash)
    x = Integer(signer.privkey)
 
    k = rand(1:order(G)) ### chooses a number from 0 to q 
    r = mod(G^k)
    kinv = modinv(k,G)
    s = mod(kinv*(h + x*r),G)
    
    if s==0
        return DSASignature(hash,key,G)
    else
        return DSASignature(hash,r,s,signer.pubkey)
    end
end

function verify(sr::DSASignature,G::CyclicGroup)
    r,s = sr.r,sr.s
    h = Integer(sr.hash)
    Y = getY(sr.pubkey,G)

    q = order(G)
    if 0<r<q || 0<s<q
        return false
    end

    sinv = modinv(s,G)
    w = mod(sinv,G)
    u1 = mod(h*w,G)
    u2 = mod(r*w,G)
    v = mod(G^u1 * Y^u2)
    if v==r
        return true
    else
        return false
    end
end
