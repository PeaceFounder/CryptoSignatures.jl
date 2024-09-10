module CryptoSignatures

using CryptoGroups: CryptoGroups, generator, concretize_type, octet, order, PGroup, ECGroup, Group
#using CryptoGroups.Curves: ECPoint, gx, gy
using CryptoGroups.Specs: MODP, ECP, EC2N, Koblitz, GroupSpec
using CryptoGroups.Utils: octet2int, int2octet, @check

using CryptoPRG: bitlength
using CryptoPRG.Verificatum: PRG

using Nettle
using Random: RandomDevice

global SEED::Vector{UInt8}
global COUNTER::Int = 0

function __init__()
    CryptoGroups.set_strict_mode(true)
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

#function generate_k(order::Integer, key::BigInt, message::Vector{UInt8}, counter::UInt8 = 0x00)
function generate_k(order::Integer, key::BigInt, e::BigInt, counter::UInt8 = 0x00)

    n = bitlength(order) 

    key_bytes = int2octet(key, n)
    e_bytes = int2octet(e, n)

    prg = PRG("sha256"; s = UInt8[SEED..., key_bytes..., e_bytes..., counter])
    k = rand(prg, BigInt; n) % order

    if k == 0 || k == 1
        return generate_k(order, key, e, counter + 0x01) 
    else
        return k
    end
end

struct DSA
    r::BigInt
    s::BigInt
end

Base.:(==)(x::DSA, y::DSA) = x.r == y.r && x.s == y.s

function sign(e::BigInt, g::G, key::BigInt; counter::UInt8 = 0x00, k::BigInt = generate_k(order(G), key, e, counter)) where G <: Group

    q = order(G)

    r = g^k % q

    s = invmod(k, q) * (e + key * r) % q

    if 1 < r < q - 1 && 1 < s < q - 1
        return DSA(r, s)
    else
        return sign(e, g, key; counter = counter + 0x01)
    end
end

function verify(e::BigInt, g::G, y::G, signature::DSA) where G <: Group

    (; r, s) = signature

    q = order(G)

    @check 1 < r < q - 1
    @check 1 < s < q - 1

    w = invmod(s, q)
    
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


struct DSAContext
    group::GroupSpec
    hasher::Union{String, Nothing}
end

CryptoGroups.generator(ctx::DSAContext) = generator(ctx.group)

generate_key(ctx::DSAContext) = generate_key(order(ctx.group))

H(message::Vector{UInt8}, hasher) = octet2int(hex2bytes(hexdigest(hasher, message)))
H(message::Vector{UInt8}, ::Nothing) = octet2int(message) # for situations where hash is computed externally


function generator_octet(spec::GroupSpec)

    G = initialize_spec_type(spec)
    g = G(generator(spec))

    return octet(g)
end

generator_octet(ctx::DSAContext) = generator_octet(ctx.group)

initialize_spec_type(curve::Union{ECP, EC2N, Koblitz}) = concretize_type(ECGroup, curve)
initialize_spec_type(modp::MODP) = concretize_type(PGroup, modp)

function sign(ctx::DSAContext, message::Vector{UInt8}, generator::Vector{UInt8}, key::BigInt; k = nothing)

    G = initialize_spec_type(ctx.group) # additional parameters could be passed here if needed for different backends
    g = G(generator) # in this setting P can also be soft typed

    e = H(message, ctx.hasher)

    # Is there a more idiomatic way to do this?
    if isnothing(k)
        return sign(e, g, key)
    else
        return sign(e, g, key; k)
    end
end

sign(ctx::DSAContext, message::Vector{UInt8}, key::BigInt; k = nothing) = sign(ctx, message, generator_octet(ctx), key; k)

function verify(ctx::DSAContext, message::Vector{UInt8}, generator::Vector{UInt8}, pbkey::Vector{UInt8}, signature::DSA)

    G = initialize_spec_type(ctx.group)

    g = G(generator) 
    y = G(pbkey)

    e = H(message, ctx.hasher)

    return verify(e, g, y, signature)
end

verify(ctx::DSAContext, message::Vector{UInt8}, pbkey::Vector{UInt8}, signature::DSA) = verify(ctx, message, generator_octet(ctx), pbkey, signature)

function public_key(ctx::DSAContext, generator::Vector{UInt8}, private_key::BigInt; mode=:compressed)
    
    G = initialize_spec_type(ctx.group)
    g = G(generator)

    y = g^private_key

    if ctx.group isa MODP
        return octet(y)
    else
        return octet(y; mode)
    end
end

public_key(ctx::DSAContext, private_key::BigInt; mode=:compressed) = public_key(ctx, generator_octet(ctx), private_key; mode)


export sign, verify, generate_key, public_key, DSA, DSAContext

end # module
