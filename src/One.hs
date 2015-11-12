{-# LANGUAGE OverloadedStrings, NoImplicitPrelude #-}
module One where

import BasePrelude
import Control.Lens
import Data.ByteString.Lens
import Data.Text.Strict.Lens
import Data.List

import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Data.ByteString as B
import qualified Data.Text as Text
import Data.ByteString.Base16 as Sixteen
import Data.ByteString.Base64 as SixtyFour

-- http://cryptopals.com/sets/1/challenges/1
hex2base64 :: ByteString -> ByteString
hex2base64 =
  SixtyFour.encode . hexDecode

-- http://cryptopals.com/sets/1/challenges/2
hexDecode :: ByteString -> ByteString
hexDecode input =
  case Sixteen.decode input of
    (output, "") ->
      output
    _ ->
      error "hexDecode: invalid size"

fixedXOR :: ByteString -> ByteString -> ByteString
fixedXOR left right =
  if B.length left == B.length right then
    B.pack (B.zipWith xor left right)
  else
    error "fixedXOR: invalid size"

-- http://cryptopals.com/sets/1/challenges/3/
frequency 'e' = 1000
frequency 'E' = 1000
frequency 'o' = 1000
frequency 'O' = 1000
frequency 'r' = 1000
frequency 'R' = 1000
frequency 's' = 1000
frequency 'S' = 1000
frequency 'A' = 1000
frequency 'a' = 1000
frequency 'T' = 1000
frequency 't' = 1000
frequency ' ' = 1000
frequency '$' = -1000
frequency '\n' = -1000
frequency c | c >= 'A' && c <= 'z' = 100
frequency c | c >= ' ' && c <= '~' = -10
frequency _ = -1000000

score :: ByteString -> Int
score s =
  getSum (foldMapOf (from packedChars . folded . to frequency) Sum s)

singleBytePossibilities :: ByteString -> [(ByteString, Int)]
singleBytePossibilities ciphertext = do
  let decoded = hexDecode ciphertext
  guess <- [0..255]
  let expanded = B.pack (replicate (B.length decoded) guess)
  let try = fixedXOR decoded expanded
  return (try, score try)

crackSingleByte :: ByteString -> (ByteString, Int)
crackSingleByte ciphertext =
  fromJust (maximumByOf traverse (compare `on` (score . fst)) (singleBytePossibilities ciphertext))

-- http://cryptopals.com/sets/1/challenges/4/
findEncrypted :: [ByteString] -> [(ByteString, ByteString, Int)]
findEncrypted candidates = do
  candidate <- candidates
  let (decrypted, ascore) = crackSingleByte candidate
  guard (ascore > 0)
  return (candidate, decrypted, ascore)

readData4 :: IO [ByteString]
readData4 = do
  s <- readFile "data/4.txt"
  let lines = Text.lines (s ^. packed)
  return (lines ^.. (traverse . re utf8))
