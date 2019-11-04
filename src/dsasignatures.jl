# TODO: Implement dsasign and verify algorithms

# """
# Returns a Signature for a given PrivateKey and data 𝑧
# pksign(pk::PrivateKey, 𝑧::Integer) -> Signature
# """
# function dsasign(pk::PrivateKey, 𝑧::Integer)
#     ### N is q of the DSA signature scheme
#     ### For generating k I could use Paillier again. 
#     𝑘 = rand(big.(0:q))
#     𝑟 = mod(value(G^k),q) ### The only place where the group enters.
    
#     ### Interesting. It was used in ECDSA
#     ### Perhaps that means for cyclic groups I need to implement modq?

#     𝑘⁻¹ = powermod(𝑘, q - 2, q) ### Why is it an inverse? Probably that needs to be covered by the group.
#     ### Under s theese are numbers. One should ensure that they are big.
#     𝑠 = mod((𝑧 + 𝑟^pk.𝑒)^𝑘⁻¹, q) ### Adding group elements. Perhaps multiplication of primes works for 
#     if 𝑠 > N / 2
#         𝑠 = N - 𝑠
#     end
#     return Signature(𝑟, 𝑠)
# end
