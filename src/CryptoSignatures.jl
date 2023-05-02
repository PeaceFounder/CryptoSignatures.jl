module CryptoSignatures

using CryptoGroups: generator, specialize, octet, <|, gx, gy, ECP, EC2N, Koblitz, CryptoGroups, ECPoint, order, modinv, MODP, PGroup
using CryptoGroups.Specs: octet2int, PRG, int2octet, bitlength

using Nettle

using Random: RandomDevice
const SEED = rand(RandomDevice(), UInt8, 128)

const COUNTER = Ref{Int}(0)


function generate_key(order::Integer)

    n = bitlength(order) 

    prg = PRG("sha256"; s = UInt8[SEED..., reinterpret(UInt8, [COUNTER[]])...])
    key = rand(prg, BigInt; n)

    COUNTER[] += 1

    return key % order
end

function generate_k(order::Integer, key::BigInt, message::Vector{UInt8})

    n = bitlength(order) 

    key_bytes = int2octet(key, n)

    prg = PRG("sha256"; s = UInt8[SEED..., key_bytes..., message...])
    k = rand(prg, BigInt; n)
    
    return k % order
end


struct DSA
    r::BigInt
    s::BigInt
end

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


function sign(ctx::ECDSAContext, message::Vector{UInt8}, generator::Vector{UInt8}, key::BigInt; k::BigInt = generate_k(order(ctx.curve), key, message))

    P = specialize(ECPoint, ctx.curve) # additional parameters could be passed here if needed for different backends
    G = P <| generator # in this setting P can also be soft typed

    e = H(message, ctx.hasher)

    R = k*G

    x̄ = gx(R) 

    n = order(P)
    r = x̄ % n

    s = modinv(k, n) * (e + key * r) % n

    return DSA(r, s)
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

    W = u₁*G + u₂*Q 
    
    #x̄ = octet(gx(W)) |> octet2int

    x̄ = gx(W)
    
    ν = x̄ % n

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


using CryptoGroups: @hex_str

function sign(ctx::DSAContext, message::Vector{UInt8}, generator::Vector{UInt8}, key::BigInt; k::BigInt = generate_k(order(ctx.group), key, message))

    G = specialize(PGroup, ctx.group)
    g = G <| generator

    e = H(message, ctx.hasher)
    q = order(G)

    r = g^k % q

    s = modinv(k, q) * (e + key * r) % q
    
    return DSA(r, s)
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

    v = g^u1 * y^u2 % q
    
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
