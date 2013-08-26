-- |
-- Module      : Crypto.Random.Entropy
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
{-# LANGUAGE CPP #-}
{-# LANGUAGE ExistentialQuantification #-}
module Crypto.Random.Entropy
    ( EntropyPool
    , EntropyReseedLevel(..)
    , createEntropyPool
    , grabEntropyPtr
    , grabEntropy
    ) where

import Control.Monad (when)
import Control.Concurrent.MVar
import System.IO.Unsafe (unsafePerformIO)
import Data.Maybe (catMaybes)
import Data.SecureMem
import Data.Word (Word8)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (plusPtr, Ptr)

import Crypto.Random.Entropy.Sig
#ifdef SUPPORT_RDRAND
import Crypto.Random.Entropy.RDRand
#endif
#ifdef WINDOWS
import Crypto.Random.Entropy.Windows
#else
import Crypto.Random.Entropy.Unix
#endif

supportedBackends :: [IO (Maybe EntropyBackend)]
supportedBackends =
    [
#ifdef SUPPORT_RDRAND
    openBackend (undefined :: RDRand),
#endif
#ifdef WINDOWS
    openBackend (undefined :: WinCryptoAPI)
#else
    openBackend (undefined :: DevRandom), openBackend (undefined :: DevURandom)
#endif
    ]

-- | Define an abstraction for the speed in which reseeding from entropy occurs.
--
-- a None level would imply that no such thing happens, and that there's no
-- way to prevent the whole stream to be guessed in a state compromise.
-- This level is only available for testing and debugging purpose, and should
-- not be used in production or real world application.
--
-- a Normal level would be typically reseeded with entropy half way before the period
-- of the CPRG is exhausted.
--
-- A High level would be typically reseeded with entropy typically around 2K to 8K of
-- random data.
data EntropyReseedLevel =
      EntropyReseed_High
    | EntropyReseed_Normal
    | EntropyReseed_None
    deriving (Show,Eq,Ord,Enum)

data EntropyBackend = forall b . EntropyHandle b => EntropyBackend b

openBackend :: EntropyHandle b => b -> IO (Maybe EntropyBackend)
openBackend b = fmap EntropyBackend `fmap` callOpen b
  where callOpen :: EntropyHandle b => b -> IO (Maybe b)
        callOpen _ = entropyOpen

gatherBackend :: EntropyBackend -> Ptr Word8 -> Int -> IO Int
gatherBackend (EntropyBackend backend) ptr n = entropyGather backend ptr n

-- | Pool of Entropy. contains a self mutating pool of entropy,
-- that is always guarantee to contains data.
data EntropyPool = EntropyPool [EntropyBackend] (MVar Int) SecureMem

-- size of entropy pool by default
defaultPoolSize :: Int
defaultPoolSize = 4096

-- | Create a new entropy pool of a specific size
--
-- While you can create as many entropy pool as you want, the pool can be shared between multiples RNGs.
createEntropyPoolWith :: Int -> IO EntropyPool
createEntropyPoolWith poolSize = do
    backends <- catMaybes `fmap` sequence supportedBackends
    when (null backends) $ fail "cannot get any source of entropy on the system"
    sm <- allocateSecureMem poolSize
    m  <- newMVar 0
    withSecureMemPtr sm $ replenish poolSize backends
    return $ EntropyPool backends m sm

-- | Create a new entropy pool with a default size.
--
-- While you can create as many entropy pool as you want, the pool can be shared between multiples RNGs.
createEntropyPool :: IO EntropyPool
createEntropyPool = createEntropyPoolWith defaultPoolSize

-- | Put a chunk of the entropy pool into a buffer
grabEntropyPtr :: Int -> EntropyPool -> Ptr Word8 -> IO ()
grabEntropyPtr n (EntropyPool backends posM sm) outPtr =
    withSecureMemPtr sm $ \entropyPoolPtr ->
        modifyMVar_ posM $ \pos ->
            copyLoop outPtr entropyPoolPtr pos n
  where poolSize = secureMemGetSize sm
        copyLoop d s pos left
            | left == 0 = return pos
            | otherwise = do
                wrappedPos <-
                    if pos == poolSize
                        then replenish poolSize backends s >> return 0
                        else return pos
                let m = min (poolSize - wrappedPos) left 
                copyBytes d (s `plusPtr` wrappedPos) m
                copyLoop (d `plusPtr` m) s (wrappedPos + m) (left - m)

-- | Grab a chunk of entropy from the entropy pool.
{-# NOINLINE grabEntropy #-}
grabEntropy :: Int -> EntropyPool -> SecureMem
grabEntropy n pool = unsafePerformIO $ do
    out <- allocateSecureMem n
    withSecureMemPtr out $ grabEntropyPtr n pool
    return $ out

replenish :: Int -> [EntropyBackend] -> Ptr Word8 -> IO ()
replenish poolSize backends ptr = loop 0 backends ptr poolSize
  where loop :: Int -> [EntropyBackend] -> Ptr Word8 -> Int -> IO ()
        loop retry [] p n | n == 0     = return ()
                          | retry == 3 = error "cannot fully replenish"
                          | otherwise  = loop (retry+1) backends p n
        loop _     (_:_)  _ 0 = return ()
        loop retry (b:bs) p n = do
            r <- gatherBackend b p n
            loop retry bs (p `plusPtr` r) (n - r)
