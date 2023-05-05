using Test
using CryptoSignatures
import CryptoGroups.Specs: MODP, ECP


group = MODP(; p=23, q=11, g=2)
ctx = DSAContext(group, "sha256")

for i in 0:255

    M = UInt8[i]

    private_key = CryptoSignatures.generate_key(ctx)
    public_key = CryptoSignatures.public_key(ctx, private_key)

    signature = CryptoSignatures.sign(ctx, M, private_key)
    @test verify(ctx, M, public_key, signature) == true

end


curve = ECP(; p = 23, a = 1, b = 4, n = 29, Gx = 0, Gy = 2)
ctx = ECDSAContext(curve, "sha256")

for i in 0:255

    M = UInt8[i]

    private_key = CryptoSignatures.generate_key(ctx)
    public_key = CryptoSignatures.public_key(ctx, private_key)

    signature = CryptoSignatures.sign(ctx, M, private_key)
    @test verify(ctx, M, public_key, signature) == true

end
