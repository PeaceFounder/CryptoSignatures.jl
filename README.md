# CryptoSignatures.jl
[![Build Status](https://travis-ci.com/PeaceFounder/CryptoSignatures.jl.svg?branch=master)](https://travis-ci.com/PeaceFounder/CryptoSignatures.jl)

`CryptoSignatures.jl` aims to be a versatile cryptographic signature library in Julia. Currently supports digital signature algorithm for all available elliptic curves in X9.62 specification. Implementation for modular prime groups is coming shortly.

## ECDSA

The first step is to select a curve to make a cryptographic signature with an elliptic curve digital signature algorithm (ECDSA). Curves from X9.62 specification are already available in `CryptoGroups.Specs` module. For instance, an elliptic prime group with 192-bit length prime modulus, also known as `secp192r1`,  can be instantiated as:

```julia
using CryptoSignatures
import CryptoGroups.Specs: Curve_P_192
ctx = ECDSAContext(Curve_P_192, "sha1")
```

where `ctx` stores all relevant parameters on how to make and verify signatures. The hash function name is specified as the second argument which is passed to `Nettle`. In case hashing is done externally to avoid hashing twice nothing can be passed as an argument like `ECDSAContext(Curve_P_192, nothing)`. 

To make a signature, first, we need to pick a key and calculate a corresponding public key:

```julia
private_key = 651056770906015076056810763456358567190100156695615665659
public_key = CryptoSignatures.public_key(ctx, private_key; mode = :uncompressed)
```

where `public_key` is stored as an octet in uncompressed notation, available are `uncompressed`, `:compressed` and `:hybrid` modes. Note that compressed mode for binary curves is limited as decompression is not implemented.

Let's say our message is `M = "abc"`. That we can sign with a private key:

```julia
k = 6140507067065001063065065565667405560006161556565665656654
signature = CryptoSignatures.sign(ctx, Vector{UInt8}(M), private_key; k)
```

where `k` is a one-time secret random number; in some instances, it is necessary to issue a signature on a different generator which can be done by passing it as an argument behind the message `sign(ctx, message, generator, private_key)`. 

The message can be verified with `verify` method using the public key and the issued signature:

```julia
CryptoSignatures.verify(ctx, Vector{UInt8}(M), public_key, signature) == true
```

returning `true` if the message had been issued by the owner of a `public_key`. In case the signature had been issued with a relative generator, the signature is verified as `verify(ctx, message, generator, public_key)`

## Security Considerations

It's important to state that the underlying implementation does not use constant time operations, thus making it vulnerable to side-channel attacks where the adversary can measure the time that it takes to make different signatures. 

Another concern is that the implementation is slow, around 10...100 times more than state-of-the-art implementations in C. This can quickly become a bottleneck and attractive avenue for adversaries performing DDOS attacks. 

It is also essential to state that only two tests are available for the signature algorithm. In practice, there are many attack vectors on how to fool improperly implemented verify function, which needs to be tested in detail. 

In a nutshell, use it for small projects, but when you become big, don't shy away from the responsibility of including this library in your security audit to make it better.

## Further Work

 An implementation of DSA for modular prime groups is coming shortly. The performance could be addressed by wrapping the OpenSSL libcrypto library for doing operations on elliptic curves. RSA signatures could be something to add, as well as a blind signature algorithm. 

 
