using Test
using CryptoSignatures
using CryptoGroups

### DSA signatures

# PrimeGroup

G = CryptoGroups.MODP160Group()
s = Signer(G) 

h = hash(3434)
signature = DSASignature(h,s,G)

@show verify(signature,G)

# EllipticGroup

G = CryptoGroups.Scep256k1Group()
s = Signer(G) 

h = hash(3434)
signature = DSASignature(h,s,G)

@show verify(signature,G)

### Old-Stuff

# import Paillier

# signer = Signer(Paillier.generate_paillier_keypair(1024))

# data = "Hello World!"
# signature = rsasign(data,hash,signer)

# @test verify(data,signature)==true

# # Now let's check message attack

# data2 = "Hello World! (Villan)"
# @test verify(data2,signature)==false




