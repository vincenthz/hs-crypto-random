crypto-random
=============

A safe API for good entropy and random generation.

Entropy pool
------------

Entropy sources
---------------

Entropy is available from the following sources:

* rdrand x86\_64 instruction where available (Intel Ivy Bridge and greater)
* windows CryptAPI
* /dev/random and /dev/urandom on unix systems.

Entropy sources are modular, and contributions to other HW random generators is
more than welcome.

Safe by default
---------------

By having an entropy pool always available with random generator, we can safely
and without having to burden the user with security details, reseed the
generator at any moment, when required, or for extra security.

Random API
----------

The random API is really simple:

    cprgGenerate :: CPRG g => Int -> g -> (ByteString, g)

