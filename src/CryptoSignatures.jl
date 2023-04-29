module CryptoSignatures

using CryptoGroups: generator, specialize, octet, <|, gx, gy, ECP, EC2N, Koblitz, CryptoGroups, ECPoint, order, modinv
using CryptoGroups.Specs: octet2int

using Nettle


struct DSA
    r::BigInt
    s::BigInt
end


struct ECDSAContext
    curve::Union{ECP, EC2N, Koblitz}
    hasher::Union{String, Nothing}
end

CryptoGroups.generator(ctx::ECDSAContext) = generator(ctx.curve)


H(message::Vector{UInt8}, hasher) = octet2int(hex2bytes(hexdigest(hasher, message)))
H(message::Vector{UInt8}, ::Nothing) = octet2int(message) # for situations where hash is computed externally


function ec_generator_octet(spec)
    x, y = generator(spec)
    return octet(x, y, spec)
end

ec_generator_octet(ctx::ECDSAContext) = ec_generator_octet(ctx.curve)


function sign(ctx::ECDSAContext, message::Vector{UInt8}, generator::Vector{UInt8}, key::BigInt; k::BigInt)

    P = specialize(ECPoint, ctx.curve) # additional parameters could be passed here if needed for different backends
    G = P <| generator # in this setting P can also be soft typed

    e = H(message, ctx.hasher)

    R = k*G

    x̄ = octet(gx(R)) |> octet2int

    n = order(P)
    r = x̄ % n

    s = modinv(k, n) * (e + key * r) % n

    return DSA(r, s)
end


sign(ctx::ECDSAContext, message::Vector{UInt8}, key::BigInt; k::BigInt) = sign(ctx, message, ec_generator_octet(ctx), key; k)



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

    x̄ = octet(gx(W)) |> octet2int
    
    ν = x̄ % n

    return ν == r
end


verify(ctx::ECDSAContext, message::Vector{UInt8}, pbkey::Vector{UInt8}, signature::DSA) = verify(ctx, message, ec_generator_octet(ctx), pbkey, signature)



function public_key(ctx::ECDSAContext, generator::Vector{UInt8}, secret_key::BigInt; mode=:compressed)
    
    P = specialize(ECPoint, ctx.curve)
    G = P <| generator

    Q = secret_key * G

    return octet(Q; mode)
end

public_key(ctx::ECDSAContext, secret_key::BigInt; mode=:compressed) = public_key(ctx, ec_generator_octet(ctx), secret_key; mode)


export sign, verify, DSA, ECDSAContext, public_key

end # module
