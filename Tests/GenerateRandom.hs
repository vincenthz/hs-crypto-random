{-# LANGUAGE PackageImports #-}
module Main where

import "crypto-random" Crypto.Random
import System.Environment
import Data.ByteString as B

gen :: String -> Int -> IO ()
gen file sz = do
    entPool <- createEntropyPool
    let cprg   = cprgCreate entPool :: SystemRNG
    let (b, _) = cprgGenerate sz cprg
    B.writeFile file b

main = do
    args <- getArgs
    case args of
        file:sz:[] -> gen file (read sz)
        _          -> error "usage: generate-random <file> <size>"
