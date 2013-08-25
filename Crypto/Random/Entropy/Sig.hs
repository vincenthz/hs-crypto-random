-- |
-- Module      : Crypto.Random.Entropy.Sig
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
module Crypto.Random.Entropy.Sig where

import Foreign.Ptr
import Data.Word (Word8)

-- | A handle to an entropy maker, either a system capability
-- or a hardware generator.
class EntropyHandle a where
    -- | try to open an handle
    entropyOpen   :: IO (Maybe a)
    -- | try to gather a number of entropy bytes into a buffer.
    -- return the number of actual bytes gathered
    entropyGather :: a -> Ptr Word8 -> Int -> IO Int
    -- | Close an open handle
    entropyClose  :: a -> IO ()
