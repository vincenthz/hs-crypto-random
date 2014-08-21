-- |
-- Module      : Crypto.Random.Test
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
-- Provide way to test usual simple statisticals test for randomness
--
{-# LANGUAGE GADTs #-}

module Crypto.Random.Test
    ( RandomTestState
    , RandomTestResult(..)
    , randomTestInitialize
    , randomTestAppend
    , randomTestFinalize
    ) where

import Data.Word
import Data.Int (Int64)
import qualified Data.ByteString.Lazy as L
import Control.Applicative
import Data.List (foldl')

import qualified Data.Vector.Mutable as M
import qualified Data.Vector as V

-- | Randomness various result relative to random bytes
data RandomTestResult = RandomTestResult
    { res_totalChars         :: Word64 -- ^ Total number of characters
    , res_entropy            :: Double -- ^ Entropy per byte
    , res_chi_square         :: Double -- ^ Chi Square
    , res_mean               :: Double -- ^ Arithmetic Mean
    , res_compressionPercent :: Double -- ^ Theorical Compression percent
    , res_probs              :: [Double] -- ^ Probability of every bucket
    } deriving (Show,Eq)

-- | Mutable random test State
newtype RandomTestState = RandomTestState (M.IOVector Word64)

-- | Initialize new state to run tests
randomTestInitialize :: IO RandomTestState
randomTestInitialize = RandomTestState <$> M.replicate 256 0

-- | Append random data to the test state
randomTestAppend :: RandomTestState -> L.ByteString -> IO ()
randomTestAppend (RandomTestState buckets) = loop
  where loop bs
            | L.null bs = return ()
            | otherwise = do
                let (b1,b2) = L.splitAt monteN bs
                mapM_ (addVec 1 . fromIntegral) $ L.unpack b1
                loop b2
        addVec a i = M.read buckets i >>= \d -> M.write buckets i $! d+a

-- | Finalize random test state into some result
randomTestFinalize :: RandomTestState -> IO RandomTestResult
randomTestFinalize (RandomTestState buckets) = (calculate . V.toList) `fmap` V.freeze buckets

monteN :: Int64
monteN = 6

calculate :: [Word64] -> RandomTestResult
calculate buckets = RandomTestResult
    { res_totalChars = totalChars
    , res_entropy    = entropy
    , res_chi_square = chisq
    , res_mean       = fromIntegral datasum / fromIntegral totalChars
    , res_compressionPercent = 100.0 * (8 - entropy) / 8.0
    , res_probs      = probs
    }
  where totalChars = sum buckets
        probs = map (\v -> fromIntegral v / fromIntegral totalChars :: Double) buckets
        entropy = foldl' accEnt 0.0 probs
        cexp    = fromIntegral totalChars / 256.0 :: Double
        (datasum, chisq) = foldl' accMeanChi (0, 0.0) [0..255]
        --chip' = abs (sqrt (2.0 * chisq) - sqrt (2.0 * 255.0 - 1.0))

        accEnt ent pr
            | pr > 0.0  = ent + (pr * xlog (1 / pr))
            | otherwise = ent
        xlog v = logBase 10 v * (log 10 / log 2)

        accMeanChi :: (Word64, Double) -> Int -> (Word64, Double)
        accMeanChi (dataSum, chiSq) i =
            let ccount = buckets !! i
                a      = fromIntegral ccount - cexp
             in (dataSum + fromIntegral i * ccount, chiSq + (a * a / cexp))
