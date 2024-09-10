using Test
using CryptoSignatures
import CryptoGroups

curve = CryptoGroups.spec(:secp192r1)
ctx = DSAContext(curve, "sha1")

private_key = CryptoSignatures.generate_key(ctx)
public_key = CryptoSignatures.public_key(ctx, private_key; mode = :uncompressed)

M = "abc"

signature = CryptoSignatures.sign(ctx, Vector{UInt8}(M), private_key)
@test CryptoSignatures.verify(ctx, Vector{UInt8}(M), public_key, signature)

