-- |
-- Module      : Crypto.Random.Entropy.Windows
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
-- code originally from the entropy package and thus is:
--   Copyright (c) Thomas DuBuisson.
--
module Crypto.Random.Entropy.Windows
    ( WinCryptoAPI
    ) where

import Data.ByteString.Internal as BI
import Data.Int (Int32)
import Data.Word (Word32, Word8)
import Foreign.C.String (CString, withCString)
import Foreign.C.Types
import Foreign.Ptr (Ptr, nullPtr, castPtr)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Utils (toBool)
import Foreign.Storable (peek)

-- Define the constants we need from WinCrypt.h 
msDefProv :: String
msDefProv = "Microsoft Base Cryptographic Provider v1.0"

provRSAFull :: Word32
provRSAFull = 1

cryptVerifyContext :: Word32
cryptVerifyContext = 0xF0000000

-- | handle to windows crypto API for random generation
newtype WinCryptoAPI = WinCryptoAPI CryptCtx

instance EntropyHandle WinCryptoAPI where
    entropyOpen                   = fmap WinCryptoAPI <$> cryptAcquireCtx
    entropyGather (WinCryptAPI h) = cryptGenRandom h
    entropyClose  (WinCryptAPI h) = cryptReleaseCtx h

type CryptCtx = Word32

-- Declare the required CryptoAPI imports 
foreign import stdcall unsafe "CryptAcquireContextA"
   c_cryptAcquireCtx :: Ptr Word32 -> CString -> CString -> Word32 -> Word32 -> IO CryptCtx
foreign import stdcall unsafe "CryptGenRandom"
   c_cryptGenRandom :: CryptCtx -> Word32 -> Ptr Word8 -> IO Int32
foreign import stdcall unsafe "CryptReleaseContext"
   c_cryptReleaseCtx :: CryptCtx -> Word32 -> IO Int32

wrap :: String -> Word32 -> ()
wrap name w 
    | toBool w == True = ()
    | otherwise        = fail name

cryptAcquireCtx :: IO (Maybe CryptCtx)
cryptAcquireCtx = 
    alloca $ \handlePtr -> 
    withCString msDefProv $ \provName -> do
        r <- toBool `fmap` c_cryptAcquireCtx handlePtr nullPtr provName provRSAFull cryptVerifyContext
        if r
            then Just `fmap` peek handlePtr
            else return Nothing

cryptGenRandom :: CryptCtx -> Ptr Word8 -> Int -> IO Int
cryptGenRandom h buf n =
    success <- toBool `fmap` c_cryptGenRandom c (fromIntegral n) buf
    return $ if success then n else 0

cryptReleaseCtx :: CryptCtx -> IO ()
cryptReleaseCtx h = wrap "c_cryptReleaseCtx" `fmap` c_cryptReleaseCtx h 0
