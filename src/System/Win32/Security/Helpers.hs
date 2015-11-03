module System.Win32.Security.Helpers
  ( parseBitFlags
  , pickName
  , parseEnumWithFlags
  , useAsPtr0
  , fromPtr0
  , mallocText
  ) where

import Data.Bits
import Data.Char (chr)
import Data.List
import Data.Maybe
import Foreign
import Foreign.C
import Text.Printf
import qualified Data.Text as T
import qualified Data.Text.Foreign as T

-- | Gets textual representation of given bit flags combination using human-readable
-- bits names.
parseBitFlags :: (Bits a, Integral b) => [(a, String)] -> (a -> b) -> a -> String
parseBitFlags names unBits bits =
  let (knownBits, rest) = foldl go ("", bits) names
  in  if rest == zeroBits
        then knownBits
        else (if null knownBits then "" else knownBits ++ " | ") ++
             printf "0x%08x" (fromIntegral $ unBits rest :: Int)
  where
    go (str, rest) (knownBit, knownName) =
      if rest .&. knownBit /= zeroBits
        then (if null str then knownName else str ++ " | " ++ knownName, rest .&. complement knownBit)
        else (str, rest)

-- | Gets textural representation of given enum value using a lookup map. If no value
-- is found in a lookup map, raw integral value is returned in hex.
pickName :: (Eq a, Integral b) => [(a, String)] -> (a -> b) -> a -> String
pickName names extractIntegral x = fromMaybe
  (printf "0x%08x" (fromIntegral $ extractIntegral x :: Int))
  (lookup x names)

-- | The hardest case. Value is supposed to be an enumeration, but several flags might also be present.
parseEnumWithFlags :: (Bits a, Integral b) => [(a, String)] -> [a] -> (a -> b) -> a -> String
parseEnumWithFlags names flags extractInt x =
  let flagMask = foldl (.|.) zeroBits flags
      flagPart = x .&. flagMask
      enumPart = x .&. complement flagMask
  in  intercalate " | " $ filter (not . null) [ parseBitFlags names extractInt flagPart, pickName names extractInt enumPart ]

-- | useAsPtr returns a length and byte buffer, but all the win32 functions
-- rely on null termination.
useAsPtr0 :: T.Text -> (Ptr CWchar -> IO a) -> IO a
useAsPtr0 t f = T.useAsPtr (T.snoc t (chr 0x0)) $ \ str _ -> f  (castPtr str)

-- This traverses the string twice. Is there a faster way?
fromPtr0 :: Ptr CWchar -> IO T.Text
fromPtr0 ptr = do
    -- length in 16-bit words.
    len <- lengthArray0 0x0000 ptr'
    -- no loss of precision here. I16 is a newtype wrapper around Int.
    T.fromPtr ptr' $ fromIntegral len
  where
    ptr' :: Ptr Word16
    ptr' = castPtr ptr

-- Allocates buffer and copies given text contents into it. You'd better run
-- this function masked.
-- Allocated buffer should be freed by calling 'free' function.
mallocText :: T.Text -> IO (Ptr Word16, Int)
mallocText t = do
  let len = T.lengthWord16 t
  buffer <- mallocBytes (len * sizeOf (undefined :: Word16))
  T.unsafeCopyToPtr t buffer
  return (buffer, len)
