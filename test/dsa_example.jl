using Test
using CryptoSignatures
import CryptoGroups.Specs: generate_qp, generate_g, MODP

q, p = generate_qp(100) # group order with 100 bits as an example (use > 2000)!
g = generate_g(p, q)

group = MODP(; p, q, g)

ctx = DSAContext(group, "sha256")

private_key = CryptoSignatures.generate_key(ctx)
public_key = CryptoSignatures.public_key(ctx, private_key)


M = "abc"

signature = CryptoSignatures.sign(ctx, Vector{UInt8}(M), private_key)
@test verify(ctx, Vector{UInt8}(M), public_key, signature) == true
