# Haskell DNS Resolver

Dns resolver in Haskell without using any third party liberary

knowing what a dns packet consist of + representing the dns packet using constructors
    see rfc, and explain each field and flag
encoding it into bytestrings to send over the internet
    straight forward
sending payload based on protocol specs (using tcp/udp and on which port)
    why dns use udp instead of tcp
decoding the response 
    decode response, write about dns name compression and how its elegant 
    and how much % of space its saving
consuming the response and do needful
    recursive nature of dns
