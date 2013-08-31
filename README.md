crypto-random
=============

A safe API for good entropy and random generation.

Entropy pool
------------

Entropy pool is a self replenishing pool of entropy, composed of entropy
made from entropy sources. It's easy to create a default one:

    pool <- createEntropyPool

Entropy sources
---------------

Entropy is available from the following sources:

* rdrand x86\_64 instruction where available (Intel Ivy Bridge and greater)
* windows CryptAPI
* /dev/random and /dev/urandom on unix systems.

Entropy sources are modular, and contributions to support other HW random
generators is more than welcome.

Safe by default
---------------

By having an entropy pool always available with random generator, we can safely
and without having to burden the user with security details, reseed the
generator at any moment, when required, or for extra security.

Generate Pseudo Random bytes
----------------------------

The random API is really simple:

    cprgGenerate :: CPRG g => Int -> g -> (ByteString, g)

which generate some bytes of randomness and return the new CPRG.
