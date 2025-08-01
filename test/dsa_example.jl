using Test
using CryptoSignatures
import CryptoGroups.Specs: MODP

p, q, g = 23, 11, 2
group = MODP(; p, q, g)

ctx = DSAContext(group, "sha256")

private_key = CryptoSignatures.generate_key(ctx)
public_key = CryptoSignatures.public_key(ctx, private_key)


M = "abc"

signature = CryptoSignatures.sign(ctx, Vector{UInt8}(M), private_key)
@test verify(ctx, Vector{UInt8}(M), public_key, signature) == true
