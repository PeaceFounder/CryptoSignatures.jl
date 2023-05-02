# Test vector taken from FIPS 186-1

using Test
using CryptoSignatures
using CryptoGroups: MODP, @hex_str
using CryptoGroups.Specs: octet2int


group = MODP(; 
             p = hex"8df2a494 492276aa 3d25759b b06869cb eac0d83a fb8d0cf7 cbb8324f 0d7882e5 d0762fc5 b7210eaf c2e9adac 32ab7aac 49693dfb f83724c2 ec0736ee 31c80291",
             q = hex"c773218c 737ec8ee 993b4f2d ed30f48e dace915f",
             g = hex"626d0278 39ea0a13 413163a5 5b4cb500 299d5522 956cefcb 3bff10f3 99ce2c2e 71cb9de5 fa24babf 58e5b795 21925c9c c42e9f6f 464b088c c572af53 e6d78802"
)

ctx = DSAContext(group, "sha1")

private_key = hex"2070b322 3dba372f de1c0ffc 7b2e3b49 8b260614" |> octet2int
public_key = CryptoSignatures.public_key(ctx, private_key)


@test public_key == hex"19131871 d75b1612 a819f29d 78d1b0d7 346f7aa7 7bb62a85 9bfd6c56 75da9d21 2d3a36ef 1672ef66 0b8c7c25 5cc0ec74 858fba33 f44c0669 9630a76b 030ee333"


M = "abc"
k = hex"358dad57 1462710f 50e254cf 1a376b2b deaadfbf" |> octet2int


signature = CryptoSignatures.sign(ctx, Vector{UInt8}(M), private_key; k)

@test signature.r == hex"8bac1ab6 6410435c b7181f95 b16ab97c 92b341c0" |> octet2int
@test signature.s == hex"41e2345f 1f56df24 58f426d1 55b4ba2d b6dcd8c8" |> octet2int


@test CryptoSignatures.verify(ctx, Vector{UInt8}(M), public_key, signature)
