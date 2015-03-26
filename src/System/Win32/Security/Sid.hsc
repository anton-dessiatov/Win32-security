{-# LANGUAGE CPP, ForeignFunctionInterface, OverloadedStrings #-}
-- | This module is a place for functions listed in MSDN "Authorization functions" section that work with security
-- identifiers.
--
-- Partially borrowed from Win32-extras package
module System.Win32.Security.Sid
  ( Sid
  , SID_NAME_USE (..)
  , sidTypeUser
  , sidTypeGroup
  , sidTypeDomain
  , sidTypeAlias
  , sidTypeWellKnownGroup
  , sidTypeDeletedAccount
  , sidTypeInvalid
  , sidTypeUnknown
  , sidTypeComputer

  , LookedUpAccount (..)

  -- * Functions
  , lookupAccountName
  , convertSidToStringSid
  ) where

import Foreign
import Foreign.C
import System.Win32.Security
import System.Win32.Types
import qualified Data.Text as T
import qualified Data.Text.Foreign as T
import qualified System.Win32.Error as E
import qualified System.Win32.Error.Foreign as E
import qualified System.Win32.Security.MarshalText as T

#include <windows.h>

newtype Sid = Sid (ForeignPtr SID)

-- | Converts SID from binary to a textual representation.
convertSidToStringSid :: Sid -> IO T.Text
convertSidToStringSid (Sid sid) =
  withForeignPtr sid $ \pSid ->
  with nullPtr $ \ pStringSid -> do
  E.failIfFalse_ "convertSidToStringSid" $
    c_ConvertSidToStringSid pSid pStringSid
  str <- peek pStringSid
  result <- T.fromPtr0 str
  _ <- localFree str
  return result

foreign import WINDOWS_CCONV unsafe "windows.h ConvertSidToStringSidW"
  c_ConvertSidToStringSid
    :: PSID
    -> Ptr LPWSTR
    -> IO BOOL

newtype SID_NAME_USE = SID_NAME_USE { sidNameUseValue :: #{type SID_NAME_USE} }
  deriving (Eq)

instance Storable SID_NAME_USE where
  sizeOf _ = #{size SID_NAME_USE}
  alignment _ = 4
  peek p = fmap SID_NAME_USE (peek $ castPtr p)
  poke p (SID_NAME_USE x) = poke (castPtr p) x

type PSID_NAME_USE = Ptr SID_NAME_USE

#{enum SID_NAME_USE, SID_NAME_USE
 , sidTypeUser = SidTypeUser
 , sidTypeGroup = SidTypeGroup
 , sidTypeDomain = SidTypeDomain
 , sidTypeAlias = SidTypeAlias
 , sidTypeWellKnownGroup = SidTypeWellKnownGroup
 , sidTypeDeletedAccount = SidTypeDeletedAccount
 , sidTypeInvalid = SidTypeInvalid
 , sidTypeUnknown = SidTypeUnknown
 , sidTypeComputer = SidTypeComputer
}

-- | A table used to lookup SID constant names for the Show instance.
sidNameUseTable :: [(SID_NAME_USE, String)]
sidNameUseTable =
  [ (sidTypeUser, "sidTypeUser")
  , (sidTypeGroup, "sidTypeGroup")
  , (sidTypeDomain, "sidTypeDomain")
  , (sidTypeAlias, "sidTypeAlias")
  , (sidTypeWellKnownGroup, "sidTypeWellKnownGroup")
  , (sidTypeDeletedAccount, "sidTypeDeletedAccount")
  , (sidTypeInvalid, "sidTypeInvalid")
  , (sidTypeUnknown, "sidTypeUnknown")
  , (sidTypeComputer, "sidTypeComputer")
  ]

instance Show SID_NAME_USE where
  show x@(SID_NAME_USE v) = case lookup x sidNameUseTable of
    Just name -> name
    Nothing   -> "SID_NAME_USE " ++ show v

data LookedUpAccount = LookedUpAccount
  { lookedUpSid                  :: Sid
  , lookedUpReferencedDomainName :: String
  , lookedUpUse                  :: SID_NAME_USE
  }

lookupAccountName :: Maybe T.Text -> T.Text -> IO (Maybe LookedUpAccount)
lookupAccountName systemName accountName =
  maybe ($ nullPtr) T.useAsPtr0 systemName $ \lpSystemName ->
  T.useAsPtr0 accountName $ \lpAccountName ->
  with 0 $ \lpcbSid ->
  with 0 $ \lpcchReferencedDomainName ->
  with (SID_NAME_USE 0) $ \lppeUse -> do
  nullPSid <- newForeignPtr_ nullPtr
  go lpSystemName lpAccountName nullPSid lpcbSid nullPtr lpcchReferencedDomainName lppeUse
  where
    go lpSystemName lpAccountName sid lpcbSid rdnBuffer lpcchReferencedDomainName lppeUse = do
      cbSid <- peek lpcbSid
      cchReferencedDomainName <- peek lpcchReferencedDomainName
      withForeignPtr sid $ \pSid -> do
        r <- c_LookupAccountNameW lpSystemName lpAccountName pSid lpcbSid rdnBuffer lpcchReferencedDomainName lppeUse
        if r
          then do
            rdn <- peekCWStringLen (rdnBuffer, fromIntegral cchReferencedDomainName - 1) -- -1 is for terminating null
            use <- peek lppeUse
            return . Just $ LookedUpAccount (Sid sid) rdn use
          else do
            err_code <- getLastError
            case err_code of
              #{const ERROR_NONE_MAPPED} -> return Nothing
              #{const ERROR_INSUFFICIENT_BUFFER} -> do
                newSid <- mallocForeignPtrBytes (fromIntegral cbSid)
                allocaBytes ((fromIntegral cchReferencedDomainName) * sizeOf (undefined :: CWchar)) $ \newRdnBuffer ->
                  go lpSystemName lpAccountName newSid lpcbSid newRdnBuffer lpcchReferencedDomainName lppeUse
              _ -> E.failWith "lookupAccountName" $ E.fromDWORD err_code

foreign import WINDOWS_CCONV unsafe "windows.h LookupAccountNameW"
  c_LookupAccountNameW
    :: LPCWSTR -- lpSystemName
    -> LPCWSTR -- lpAccountName
    -> PSID -- Sid
    -> LPDWORD -- cbSid
    -> LPWSTR -- ReferencedDomainName
    -> LPDWORD -- cchReferencedDomainName
    -> PSID_NAME_USE -- peUse
    -> IO BOOL
