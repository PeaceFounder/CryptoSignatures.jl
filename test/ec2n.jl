using Test
using CryptoSignatures
using CryptoGroups.Specs: EC2N, PB
using CryptoGroups.Utils: @hex_str


basis = PB(hex"80000000 00000000 00000000 00000000 00000000 00000201", 191)

curve = EC2N(basis; 
                  a = hex"2866537B 67675263 6A68F565 54E12640 276B649E F7526267",
                  b = hex"2E45EF57 1F00786F 67B0081B 9495A3D9 5462F5DE 0AA185EC",
                  G = hex"04 36B3DAF8 A23206F9 C4F299D7 B21A9C36 9137F2C8 4AE1AA0D 765BE734 33B3F95E 332932E7 0EA245CA 2418EA0E F98018FB",
                  n = 1569275433846670190958947355803350458831205595451630533029,
                  cofactor = 2
)

ctx = DSAContext(curve, "sha1")


d = 1275552191113212300012030439187146164646146646466749494799
Q = public_key(ctx, d; mode = :uncompressed)

@test Q == hex"04 5DE37E75 6BD55D72 E3768CB3 96FFEB96 2614DEA4 CE28A2E7 55C0E0E0 2F5FB132 CAF416EF 85B229BB B8E13520 03125BA1"

M = "abc"
k = 1542725565216523985789236956265265265235675811949404040041

signature = CryptoSignatures.sign(ctx, Vector{UInt8}(M), d; k)

@test signature.r == 87194383164871543355722284926904419997237591535066528048
@test signature.s == 308992691965804947361541664549085895292153777025772063598

@test CryptoSignatures.verify(ctx, Vector{UInt8}(M), Q, signature)
