-- |
-- Module      : Crypto.Random.Generator
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
module Crypto.Random.Generator
    ( CPRG(..)
    ) where

import Data.ByteString (ByteString)
import Crypto.Random.Entropy (EntropyPool)

-- | Cryptographic Pseudo Random Generator
class CPRG gen where
    -- | Create a new CPRG using an object of the CryptoGenerator class
    -- and with an explicit reference to an EntropyPool.
    cprgCreate :: EntropyPool -> gen

    -- | Give the ability to set a threshold of byte generated that after
    -- being exceeded will result in a reseed with some stateful entropy
    -- after a call to 'cprgGenerate'
    --
    -- If this threshold is exceeded during the set operation, the
    -- rng should be reseeded here.
    --
    -- If this value is set to 0, no reseeding will be done and the
    -- output will be completely predicable. This is not a recommended
    -- level except for debugging and testing purpose.
    cprgSetReseedThreshold :: Int -> gen -> gen

    -- | Fork a CPRG into a new independent CPRG.
    --
    -- As entropy is mixed to generate safely a new generator,
    -- 2 calls with the same CPRG will not produce the same output.
    cprgFork :: gen -> (gen, gen)

    -- | Generate a number of bytes using the CPRG.
    --
    -- Given one CPRG, the generated bytes will always be the same.
    --
    -- However the returned CPRG might have been reseeded with entropy bits,
    -- so 2 calls with the same CPRG will not necessarily result in the same next CPRG.
    cprgGenerate :: Int -> gen -> (ByteString, gen)

    -- | Similar to cprgGenerate except that the random data is mixed with pure entropy,
    -- so the result is not reproducible after use, but it provides more guarantee,
    -- theorically speaking, in term of the randomness generated.
    cprgGenerateWithEntropy :: Int -> gen -> (ByteString, gen)
