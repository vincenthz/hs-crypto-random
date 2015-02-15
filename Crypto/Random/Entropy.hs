-- |
-- Module      : Crypto.Random.Entropy
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
{-# LANGUAGE CPP #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.Random.Entropy
    ( EntropyPool
    , createEntropyPool
    , createTestEntropyPool
    , grabEntropyPtr
    , grabEntropy
    , grabEntropyIO
    ) where

import Control.Monad (when)
import Control.Concurrent.MVar
import System.IO.Unsafe (unsafePerformIO)
import Data.Maybe (catMaybes)
import Data.SecureMem
import Data.Typeable (Typeable)
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B
import Data.Word (Word8)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (plusPtr, Ptr)
import Foreign.ForeignPtr (withForeignPtr)

import Crypto.Random.Entropy.Source
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

data EntropyBackend = forall b . EntropySource b => EntropyBackend b

newtype TestEntropySource = TestEntropySource ByteString

instance EntropySource TestEntropySource where
    entropyOpen    = return Nothing
    entropyGather (TestEntropySource bs) dst n
        | len == 1  = B.memset dst (B.index bs 0) (fromIntegral n) >> return n
        | otherwise = do withForeignPtr fptr $ \ptr -> loop dst (ptr `plusPtr` o) n
                         return n
      where (B.PS fptr o len) = bs
            loop d s i
                | i == 0    = return ()
                | i <= len  = B.memcpy d s (fromIntegral i)
                | otherwise = B.memcpy d s (fromIntegral len) >> loop (d `plusPtr` len) s (i-len)
    entropyClose _ = return ()

openBackend :: EntropySource b => b -> IO (Maybe EntropyBackend)
openBackend b = fmap EntropyBackend `fmap` callOpen b
  where callOpen :: EntropySource b => b -> IO (Maybe b)
        callOpen _ = entropyOpen

gatherBackend :: EntropyBackend -> Ptr Word8 -> Int -> IO Int
gatherBackend (EntropyBackend backend) ptr n = entropyGather backend ptr n

-- | Pool of Entropy. contains a self mutating pool of entropy,
-- that is always guarantee to contains data.
data EntropyPool = EntropyPool [EntropyBackend] (MVar Int) SecureMem
  deriving Typeable

-- size of entropy pool by default
defaultPoolSize :: Int
defaultPoolSize = 4096

-- | Create a new entropy pool of a specific size
--
-- You can create as many entropy pools as you want, and a given pool can be shared between multiples RNGs.
createEntropyPoolWith :: Int -> [EntropyBackend] -> IO EntropyPool
createEntropyPoolWith poolSize backends = do
    when (null backends) $ fail "cannot get any source of entropy on this system"
    sm <- allocateSecureMem poolSize
    m  <- newMVar 0
    withSecureMemPtr sm $ replenish poolSize backends
    return $ EntropyPool backends m sm

-- | Create a new entropy pool with a default size.
--
-- While you can create as many entropy pool as you want, the pool can be shared between multiples RNGs.
createEntropyPool :: IO EntropyPool
createEntropyPool = do
    backends <- catMaybes `fmap` sequence supportedBackends
    createEntropyPoolWith defaultPoolSize backends

-- | Create a dummy entropy pool that is deterministic, and
-- dependant on the input bytestring only.
--
-- This is stricly reserved for testing purpose when a deterministic seed need
-- to be generated with deterministic RNGs.
--
-- Do not use in production code.
createTestEntropyPool :: ByteString -> EntropyPool
createTestEntropyPool bs
    | B.null bs = error "cannot create entropy pool from an empty bytestring"
    | otherwise = unsafePerformIO $ createEntropyPoolWith defaultPoolSize [EntropyBackend $ TestEntropySource bs]

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
grabEntropyIO :: Int -> EntropyPool -> IO SecureMem
grabEntropyIO n pool = do
    out <- allocateSecureMem n
    withSecureMemPtr out $ grabEntropyPtr n pool
    return $ out

-- | Grab a chunk of entropy from the entropy pool.
--
-- Great care need to be taken here when using the output,
-- as this use unsafePerformIO to actually get entropy.
--
-- Use grabEntropyIO if unsure.
{-# NOINLINE grabEntropy #-}
grabEntropy :: Int -> EntropyPool -> SecureMem
grabEntropy n pool = unsafePerformIO $ grabEntropyIO n pool

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
