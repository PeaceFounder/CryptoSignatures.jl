# CryptoSignatures.jl
[![Build Status](https://travis-ci.com/PeaceFounder/CryptoSignatures.jl.svg?branch=master)](https://travis-ci.com/PeaceFounder/CryptoSignatures.jl)

`CryptoSignatures.jl` aims to be a versatile cryptographic signature library in Julia. Currently supports digital signature algorithm for all available elliptic curves in X9.62 specification. Implementation for modular prime groups is coming shortly.

## ECDSA

The first step is to select a curve to make a cryptographic signature with an elliptic curve digital signature algorithm (ECDSA). Curves from X9.62 specification are already available in `CryptoGroups.Specs` module. For instance, an elliptic prime group with 192-bit length prime modulus, also known as `secp192r1`,  can be instantiated as:

```julia
using CryptoSignatures
import CryptoGroups

curve = CryptoGroups.curve("secp192r1")
ctx = ECDSAContext(curve, "sha1")
```

where `ctx` stores all relevant parameters on how to make and verify signatures. The second argument specifies a hash function name, which is forwarded to `Nettle`. In case hashing is done externally to avoid hashing twice, nothing can be passed as an argument like `ECDSAContext(Curve_P_192, nothing)`. 

To make a signature, first, we need to pick a key and calculate a corresponding public key:

```julia
private_key = CryptoSignatures.generate_key(ctx)
public_key = CryptoSignatures.public_key(ctx, private_key; mode = :uncompressed)
```

where `public_key` is stored as an octet in uncompressed notation, available are `uncompressed`, `:compressed` and `:hybrid` modes. Note that compressed mode for binary curves is limited as decompression is not implemented.

Let's say our message is `M = "abc"`. That we can sign with a private key:

```julia
signature = CryptoSignatures.sign(ctx, Vector{UInt8}(M), private_key)
```

Note that the signature is issued with a `k` value derived deterministically with a pseudorandom number generator where a seed contains a message, private key and a global seed `CryptoSignatures.SEED` computed when module is loaded. A signature on a relative generator which can be done by passing it as an argument behind the message `sign(ctx, message, generator, private_key)`.

The message can be verified with `verify` method using the public key and the issued signature:

```julia
CryptoSignatures.verify(ctx, Vector{UInt8}(M), public_key, signature) == true
```

returning `true` if the message had been issued by the owner of a `public_key`. In case the signature had been issued with a relative generator, it is verified as `verify(ctx, message, generator, public_key)`.

## DSA

To use an ordinary DSA with modular arithmetics, we need to instantiate the `DSAContext`. To do so, we need to select a prime modulus `p` for which we know group order `q` and generator `g`. With `CryptoGroups` we can generate those parameters and then use them for creating `DSAContext`:

```julia
using CryptoSignatures
import CryptoGroups.Specs: generate_pq, generate_g, MODP

p, q = generate_qp(100) # group order with 100 bits as an example (use > 2000)!
g = generate_g(p, q)

group = MODP(; p, q, g)

ctx = DSAContext(group, "sha1")
```

As for `ECDSA` context, we generate a private key and a public key:

```julia
private_key = CryptoSignatures.generate_key(ctx)
public_key = CryptoSignatures.public_key(ctx, private_key)
```

Which can be used to sign and verify messages as before:

```julia
M = "abc"

signature = CryptoSignatures.sign(ctx, Vector{UInt8}(M), private_key)

verify(ctx, Vector{UInt8}(M), public_key, signature) == true
```

## Security Considerations

It's important to state that the underlying implementation does not use constant time operations, thus making it vulnerable to side-channel attacks where the adversary can measure the time that it takes to make different signatures. 

Another concern is that the implementation is slow, around 10...100 times more than state-of-the-art implementations in C. This can quickly become a bottleneck and attractive avenue for adversaries performing DDOS attacks. 

It is also essential to state that only two tests are available for the signature algorithm. In practice, there are many attack vectors on how to fool improperly implemented verify function, which needs to be tested in detail. 

In a nutshell, use it for small projects, but when you become big, don't shy away from the responsibility of including this library in your security audit to make it better.

## Further Work

The performance could be addressed by wrapping the OpenSSL libcrypto library for doing operations on elliptic curves. RSA signatures could be something to add, as well as a blind signature algorithm. 

 
