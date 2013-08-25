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
    -- * Random generation
    , CPRG(..)
    -- * System generator
    , SystemRNG
    ) where

import Crypto.Random.Entropy
import Crypto.Random.Generator
import qualified Data.ByteString.Internal as B (unsafeCreate)

-- | System entropy generator.
data SystemRNG = SystemRNG EntropyPool

instance CPRG SystemRNG where
    cprgCreate entPool                   = SystemRNG entPool
    cprgFork (SystemRNG entPool)         = cprgCreate entPool
    cprgGenerate n g@(SystemRNG entPool) = (B.unsafeCreate n (grabEntropyPtr n entPool), g)
