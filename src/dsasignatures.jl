struct DSASignature{H,P} <: AbstractSignature
    hash::H # hash could have its own type
    r 
    s
    pubkey::P #
end

import Base.mod
mod(G::CyclicGroup) = mod(value(G),order(G))
mod(n::Integer,G::CyclicGroup) = mod(n,order(G))

# https://github.com/zydeon/DSA/blob/master/DSA.py
function modinv_euclidean(z::Integer,a::Integer)
    if 0<z<a
	i = a
	j = z
	y1 = BigInt(1)
	y2 = BigInt(0)
	while j > 0
	    q = div(i,j)
	    r = i-j*q
	    y = y2 - y1*q
	    i, j = j, r
	    y2, y1 = y1, y
	    if i == 1
		return mod(y2,a)
            end
        end
    else
        error("Inverse Error")
    end
end

modinv_fermat(k::Integer,a::Integer) = powermod(k,a-2,a)

modinv(k::Integer,G::CyclicGroup) = modinv_euclidean(k,order(G))

function DSASignature(hash,signer::AbstractSigner)

    h = BigInt(hash)
    x = BigInt(signer.privkey)
    G = signer.G
 
    k = rand(1:order(G)) ### chooses a number from 0 to q 
    r = mod(G^k)
    kinv = modinv(k,G)
    s = mod(kinv*(h + x*r),G)
    
    # This always works for modinv_fermat
    # s < order(G)/2 || s = order(G) - s

    if s==0
        return DSASignature(hash,signer,G)
    else
        return DSASignature(hash,r,s,signer.pubkey)
    end
end

function verify(sr::DSASignature,G::CyclicGroup)
    r,s = sr.r,sr.s
    h = BigInt(sr.hash)
    Y = typeof(G)(sr.pubkey,G) 

    0<r<order(G) || return false
    0<s<order(G) || return false

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
