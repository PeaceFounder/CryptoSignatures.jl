module CryptoSignatures

using CryptoGroups: generator, specialize, octet, <|, gx, gy, ECP, EC2N, Koblitz, CryptoGroups, ECPoint, order, modinv, MODP, PGroup
using CryptoGroups.Specs: octet2int, PRG, int2octet, bitlength

using Nettle
using Random: RandomDevice

global SEED::Vector{UInt8}
global COUNTER::Int = 0

function __init__()
    global SEED = rand(RandomDevice(), UInt8, 128)
end


function generate_key(order::Integer)

    n = bitlength(order) 

    prg = PRG("sha256"; s = UInt8[SEED..., reinterpret(UInt8, [COUNTER])...])
    key = rand(prg, BigInt; n) % order

    global COUNTER += 1

    # Generally only relevant when exponents are small
    if key == 0 || key == 1
        return generate_key(order)
    else
        return key
    end
end

function generate_k(order::Integer, key::BigInt, message::Vector{UInt8}, counter::UInt8 = 0x00)

    n = bitlength(order) 

    key_bytes = int2octet(key, n)

    prg = PRG("sha256"; s = UInt8[SEED..., key_bytes..., message..., counter])
    k = rand(prg, BigInt; n) % order

    if k == 0 || k == 1
        return generate_k(order, key, message, counter + 0x01) 
    else
        return k
    end
end


struct DSA
    r::BigInt
    s::BigInt
end

Base.:(==)(x::DSA, y::DSA) = x.r == y.r && x.s == y.s

struct ECDSAContext
    curve::Union{ECP, EC2N, Koblitz}
    hasher::Union{String, Nothing}
end

CryptoGroups.generator(ctx::ECDSAContext) = generator(ctx.curve)

generate_key(ctx::ECDSAContext) = generate_key(order(ctx.curve))

H(message::Vector{UInt8}, hasher) = octet2int(hex2bytes(hexdigest(hasher, message)))
H(message::Vector{UInt8}, ::Nothing) = octet2int(message) # for situations where hash is computed externally


function generator_octet(spec::Union{ECP, EC2N, Koblitz})
    x, y = generator(spec)
    return octet(x, y, spec)
end

generator_octet(ctx::ECDSAContext) = generator_octet(ctx.curve)


function sign(ctx::ECDSAContext, message::Vector{UInt8}, generator::Vector{UInt8}, key::BigInt; counter::UInt8 = 0x00, k::BigInt = generate_k(order(ctx.curve), key, message, counter))

    P = specialize(ECPoint, ctx.curve) # additional parameters could be passed here if needed for different backends
    G = P <| generator # in this setting P can also be soft typed

    e = H(message, ctx.hasher)

    R = k*G

    x̄ = gx(R) 

    n = order(P)
    r = x̄ % n

    s = modinv(k, n) * (e + key * r) % n

    if 1 < r < n - 1 && 1 < s < n - 1
        return DSA(r, s)
    else
        return sign(ctx, message, generator, key; counter = counter + 0x01)
    end
end


sign(ctx::ECDSAContext, message::Vector{UInt8}, key::BigInt; kwargs...) = sign(ctx, message, generator_octet(ctx), key; kwargs...)


function verify(ctx::ECDSAContext, message::Vector{UInt8}, generator::Vector{UInt8}, pbkey::Vector{UInt8}, signature::DSA)

    (; r, s) = signature

    P = specialize(ECPoint, ctx.curve) 
    G = P <| generator 
    Q = P <| pbkey

    e = H(message, ctx.hasher)
    n = order(P)

    @assert 1 < r < n - 1
    @assert 1 < s < n - 1

    c = modinv(s, n)

    u₁ = e*c % n
    u₂ = r*c % n

    if u₁ == 0
        W = u₂*Q 
    elseif u₂ == 0
        W = u₁*G
    else
        W = u₁*G + u₂*Q 
    end
    
    x̄ = gx(W)
    ν = x̄ % n # I could also rewrite it as ν = W % n

    return ν == r
end


verify(ctx::ECDSAContext, message::Vector{UInt8}, pbkey::Vector{UInt8}, signature::DSA) = verify(ctx, message, generator_octet(ctx), pbkey, signature)



function public_key(ctx::ECDSAContext, generator::Vector{UInt8}, private_key::BigInt; mode=:compressed)
    
    P = specialize(ECPoint, ctx.curve)
    G = P <| generator

    Q = private_key * G

    return octet(Q; mode)
end

public_key(ctx::ECDSAContext, private_key::BigInt; mode=:compressed) = public_key(ctx, generator_octet(ctx), private_key; mode)


struct DSAContext
    group::MODP
    hasher::Union{String, Nothing}
end


CryptoGroups.generator(ctx::DSAContext) = generator(ctx.group)


function generator_octet(spec::MODP)
    g = generator(spec)
    return octet(g, spec)
end

generator_octet(ctx::DSAContext) = generator_octet(ctx.group)


function sign(ctx::DSAContext, message::Vector{UInt8}, generator::Vector{UInt8}, key::BigInt; counter::UInt8 = 0x00, k::BigInt = generate_k(order(ctx.group), key, message, counter))

    G = specialize(PGroup, ctx.group)
    g = G <| generator

    e = H(message, ctx.hasher)
    q = order(G)

    r = g^k % q

    s = modinv(k, q) * (e + key * r) % q

    if 1 < r < q - 1 && 1 < s < q - 1
        return DSA(r, s)
    else
        return sign(ctx, message, generator, key; counter = counter + 0x01)
    end
end


sign(ctx::DSAContext, message::Vector{UInt8}, key::BigInt; kwargs...) = sign(ctx, message, generator_octet(ctx), key; kwargs...)


function verify(ctx::DSAContext, message::Vector{UInt8}, generator::Vector{UInt8}, pbkey::Vector{UInt8}, signature::DSA)

    (; r, s) = signature
    G = specialize(PGroup, ctx.group)

    g = G <| generator
    y = G <| pbkey


    e = H(message, ctx.hasher)    
    q = order(G)

    @assert 1 < r < q - 1
    @assert 1 < s < q - 1

    w = modinv(s, q)
    
    u1 = e * w % q
    u2 = r * w % q

    # # Raising group element to 0 not allowed. Perhaps need to change that.
    if u1 == 0
        v = y^u2 % q
    elseif u2 == 0
        v = g^u1 % q
    else
        v = g^u1 * y^u2 % q
    end
    
    return v == r
end

verify(ctx::DSAContext, message::Vector{UInt8}, pbkey::Vector{UInt8}, signature::DSA) = verify(ctx, message, generator_octet(ctx), pbkey, signature)



function public_key(ctx::DSAContext, generator::Vector{UInt8}, private_key::BigInt)

    G = specialize(PGroup, ctx.group)

    g = G <| generator 

    Q = g^private_key

    return octet(Q)
end

public_key(ctx::DSAContext, private_key::BigInt) = public_key(ctx, generator_octet(ctx), private_key)

generate_key(ctx::DSAContext) = generate_key(order(ctx.group))

export sign, verify, DSA, ECDSAContext, public_key, DSAContext

end # module
