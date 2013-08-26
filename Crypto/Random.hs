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
    , EntropyReseedLevel(..)
    , createEntropyPool
    -- * Random generation
    , CPRG(..)
    -- * System generator
    , SystemRNG
    ) where

import Crypto.Random.Entropy
import Crypto.Random.Generator
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
    cprgCreate entPool _                 = SystemRNG entPool
    cprgFork lvl r@(SystemRNG entPool)   = (r, cprgCreate entPool lvl)
    cprgGenerate n g@(SystemRNG entPool) = (B.unsafeCreate n (grabEntropyPtr n entPool), g)
