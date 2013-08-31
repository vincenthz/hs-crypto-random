-- |
-- Module      : Crypto.Random
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
-- Provide a safe abstraction for cryptographic pseudo
-- random generator.
--
{-# LANGUAGE ExistentialQuantification #-}
module Crypto.Random
    (
    -- * Entropy
      EntropyPool
    , createEntropyPool
    , grabEntropy
    -- * Random generation
    , CPRG(..)
    , withRandomBytes
    -- * System generator
    , SystemRNG
    ) where

import Crypto.Random.Entropy
import Crypto.Random.Generator
import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as B (unsafeCreate)

-- | System entropy generator.
--
-- This generator doesn't use the entropy reseed level, as the only bytes
-- generated are comping from the entropy pool already.
--
-- This generator doesn't create reproducible output, and might be difficult to
-- use for testing and debugging purpose, but otherwise for real world use case
-- should be fine.
data SystemRNG = SystemRNG EntropyPool

instance CPRG SystemRNG where
    cprgCreate entPool                   = SystemRNG entPool
    cprgSetReseedThreshold _ r           = r
    cprgFork r@(SystemRNG entPool)       = (r, cprgCreate entPool)
    cprgGenerate n g@(SystemRNG entPool) = (B.unsafeCreate n (grabEntropyPtr n entPool), g)
    -- we don't need to do anything different when generating withEntropy, as the generated
    -- bytes are already stricly entropy bytes.
    cprgGenerateWithEntropy n g          = cprgGenerate n g

-- | generate @len random bytes and mapped the bytes to the function @f.
--
-- This is equivalent to use Control.Arrow 'first' with 'cprgGenerate'
withRandomBytes :: CPRG g => g -> Int -> (ByteString -> a) -> (a, g)
withRandomBytes rng len f = (f bs, rng')
  where (bs, rng') = cprgGenerate len rng
