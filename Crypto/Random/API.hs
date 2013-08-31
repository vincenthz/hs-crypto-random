-- |
-- Module      : Crypto.Random.API
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
-- Deprecated interface for compatibility of crypto-random-api user
-- with crypto-random
--
module Crypto.Random.API
    ( CPRG(..)
    , cprgGenBytes
    , genRandomBytes
    , genRandomBytes'
    , withRandomBytes
    ) where

import Data.ByteString (ByteString)
import Crypto.Random

-- | Generate bytes using the CPRG and the number specified.
--
-- For user of the API, it's recommended to use genRandomBytes
-- instead of this method directly. the CPRG need to be able
-- to supply at minimum 2^20 bytes at a time.
cprgGenBytes :: CPRG g => Int -> g -> (ByteString, g)
cprgGenBytes n cprg = cprgGenerate n cprg

-- | Generate bytes using the cprg in parameter.
--
-- If the number of bytes requested is really high,
-- it's preferable to use 'genRandomBytes' for better memory efficiency.
{-# DEPRECATED genRandomBytes "use cprgGenerate from Crypto.Random instead" #-}
genRandomBytes :: CPRG g    
               => Int -- ^ number of bytes to return
               -> g   -- ^ CPRG to use
               -> (ByteString, g)  
genRandomBytes n cprg = cprgGenerate n cprg

-- | Generate bytes using the cprg in parameter.
--
-- This is not tail recursive and an excessive len (>= 2^29) parameter would
-- result in stack overflow.
genRandomBytes' :: CPRG g => Int -- ^ number of bytes to return
                          -> g   -- ^ CPRG to use
                          -> ([ByteString], g)
genRandomBytes' len rng
    | len < 0    = error "genBytes: cannot request negative amount of bytes."
    | otherwise  = loop rng len
            where loop g n
                    | n == 0  = ([], g)
                    | otherwise = let itBytes  = min (2^(20:: Int)) n
                                      (bs, g') = cprgGenBytes itBytes g
                                      (l, g'') = genRandomBytes' (n-itBytes) g'
                                   in (bs:l, g'')
