using Test
using CryptoSignatures
using CryptoGroups

function signaturetest(s,G)
    @test verify(s,G)
    
    # Changing message
    
    vs1 = DSASignature(signature.hash+1,signature.r,signature.s,signature.pubkey)
    @test verify(vs1,G)==false

    # Changing signer

    s = Signer(G) 
    vs2 = DSASignature(signature.hash,signature.r,signature.s,s.pubkey)
    @test verify(vs2,G)==false

    # Tampering the signature
    
    vs3 = DSASignature(signature.hash,signature.r+1,signature.s,signature.pubkey)
    @test verify(vs3,G)==false

    vs4 = DSASignature(signature.hash,signature.r,signature.s+1,signature.pubkey)
    @test verify(vs4,G)==false
end

### DSA signatures

# PrimeGroup

G = CryptoGroups.MODP160Group()
s = Signer(G) 

h = hash(3434)
signature = DSASignature(h,s,G)

signaturetest(signature,G)

# EllipticGroup

G = CryptoGroups.Scep256k1Group()
s = Signer(G) 

h = hash(3434)
signature = DSASignature(h,s,G)

signaturetest(signature,G)


