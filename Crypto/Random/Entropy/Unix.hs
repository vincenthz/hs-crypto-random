-- |
-- Module      : Crypto.Random.Entropy.Unix
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
{-# LANGUAGE ScopedTypeVariables #-}
module Crypto.Random.Entropy.Unix
    ( DevRandom
    , DevURandom
    ) where

import Foreign.Ptr
import Data.Word (Word8)
import Crypto.Random.Entropy.Source
import Control.Exception as E
import System.Posix.Types (Fd)
import System.Posix.IO

type H = Fd

-- | Entropy device /dev/random on unix system 
newtype DevRandom  = DevRandom H

-- | Entropy device /dev/urandom on unix system 
newtype DevURandom = DevURandom H

instance EntropySource DevRandom where
    entropyOpen                 = fmap DevRandom `fmap` openDev "/dev/random"
    entropyGather (DevRandom h) = gatherDevEntropy h
    entropyClose (DevRandom h)  = closeDev h

instance EntropySource DevURandom where
    entropyOpen                  = fmap DevURandom `fmap` openDev "/dev/urandom"
    entropyGather (DevURandom h) = gatherDevEntropy h
    entropyClose (DevURandom h)  = closeDev h

openDev :: String -> IO (Maybe H)
openDev filepath = (Just `fmap` openFd filepath ReadOnly Nothing fileFlags)
    `E.catch` \(_ :: IOException) -> return Nothing
  where fileFlags = defaultFileFlags { nonBlock = True }

closeDev :: H -> IO ()
closeDev h = closeFd h

gatherDevEntropy :: H -> Ptr Word8 -> Int -> IO Int
gatherDevEntropy fd ptr sz =
     (fromIntegral `fmap` fdReadBuf fd ptr (fromIntegral sz))
    `E.catch` \(_ :: IOException) -> return 0
