using CryptoSignatures
using Test

import Paillier

signer = Signer(Paillier.generate_paillier_keypair(1024))

data = "Hello World!"
signature = sign(data,SHA256,signer)

@test verify(data,signature)==true

# Now let's check message attack

data2 = "Hello World! (Villan)"
@test verify(data2,signature)==false




