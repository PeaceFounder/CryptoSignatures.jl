using Test
using CryptoSignatures
using CryptoGroups.Specs: ECP
using CryptoGroups.Utils: @hex_str

curve = ECP(;
                 p = 6277101735386680763835789423207666416083908700390324961279,
                 n = 6277101735386680763835789423176059013767194773182842284081,
                 cofactor = 1,
                 a = hex"FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF FFFFFFFC",
                 b = hex"64210519 E59C80E7 0FA7E9AB 72243049 FEB8DEEC C146B9B1",
                 G = hex"03 188DA80E B03090F6 7CBF20EB 43A18800 F4FF0AFD 82FF1012",
)

ctx = ECDSAContext(curve, "sha1")


d = 651056770906015076056810763456358567190100156695615665659
Q = public_key(ctx, d)

@test Q == hex"02 62B12D60 690CDCF3 30BABAB6 E69763B4 71F994DD 702D16A5"

M = "abc"
k = 6140507067065001063065065565667405560006161556565665656654

signature = CryptoSignatures.sign(ctx, Vector{UInt8}(M), d; k)

@test signature.r == 3342403536405981729393488334694600415596881826869351677613
@test signature.s == 5735822328888155254683894997897571951568553642892029982342


@test CryptoSignatures.verify(ctx, Vector{UInt8}(M), Q, signature)
