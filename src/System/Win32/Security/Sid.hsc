{-# LANGUAGE CPP, ForeignFunctionInterface, OverloadedStrings, RankNTypes #-}
-- | This module is a place for functions listed in MSDN "Authorization functions" section that work with security
-- identifiers.
--
-- Partially borrowed from Win32-extras package
module System.Win32.Security.Sid
  ( Sid (..)
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
  , isValidSid
  , getLengthSid
  , lookupAccountName
  , lookupAccountSid
  , convertSidToStringSid

  , getProcessUserSid
  , getCurrentProcess
  ) where

import Data.Maybe (fromJust)
import Foreign
import Foreign.C
import System.IO.Unsafe
import System.Win32.Process
import System.Win32.Security
import System.Win32.Types
import qualified Data.Text as T
import qualified Data.Text.Foreign as T
import qualified System.Win32.Error as E
import qualified System.Win32.Error.Foreign as E
import qualified System.Win32.Security.Helpers as SH

#include <windows.h>

-- The data type encapsulates a function that allows anyone to perform an operation with the
-- SID pointer. This is done to fit both explicitly allocated SIDs (via closure's reference to
-- foreign ptr) and ones that are parts of larger structures, such as security descriptors.
newtype Sid = Sid { withSidPtr :: forall a. (PSID -> IO a) -> IO a }

-- | Converts SID from binary to a textual representation.
convertSidToStringSid :: Sid -> IO T.Text
convertSidToStringSid sid =
  withSidPtr sid $ \pSid ->
  with nullPtr $ \ pStringSid -> do
  E.failIfFalse_ "ConvertSidToStringSid" $
    c_ConvertSidToStringSid pSid pStringSid
  str <- peek pStringSid
  result <- SH.fromPtr0 str
  _ <- localFree str
  return result

foreign import WINDOWS_CCONV unsafe "windows.h ConvertSidToStringSidW"
  c_ConvertSidToStringSid
    :: PSID
    -> Ptr LPWSTR
    -> IO BOOL

-- | Checks the given SID for a validity. Return False if revision number is outside a known range
-- or if the number of subauthorities is more that maximum.
isValidSid :: Sid -> Bool
isValidSid sid = unsafePerformIO $ withSidPtr sid c_IsValidSid

foreign import WINDOWS_CCONV unsafe "windows.h IsValidSid"
  c_IsValidSid
    :: PSID
    -> IO BOOL

-- | Gets the length, in bytes, of given valid Sid. If Sid is not valid, the return value is undefined.
getLengthSid :: Sid -> Int
getLengthSid sid = fromIntegral . unsafePerformIO $ withSidPtr sid c_GetLengthSid

foreign import WINDOWS_CCONV unsafe "windows.h GetLengthSid"
  c_GetLengthSid
    :: PSID
    -> IO DWORD

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
  , lookedUpAccountName          :: T.Text
  , lookedUpReferencedDomainName :: T.Text
  , lookedUpUse                  :: SID_NAME_USE
  }

lookupAccountName :: Maybe T.Text -> T.Text -> IO (Maybe LookedUpAccount)
lookupAccountName systemName accountName =
  maybe ($ nullPtr) SH.useAsPtr0 systemName $ \lpSystemName ->
  SH.useAsPtr0 accountName $ \lpAccountName ->
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
            rdn <- T.fromPtr (castPtr rdnBuffer) (fromIntegral cchReferencedDomainName - 1) -- -1 is for terminating null
            use <- peek lppeUse
            return . Just $ LookedUpAccount (Sid $ withForeignPtr sid) accountName rdn use
          else do
            err_code <- getLastError
            case err_code of
              #{const ERROR_NONE_MAPPED} -> return Nothing
              #{const ERROR_INSUFFICIENT_BUFFER} -> do
                newCbSid <- peek lpcbSid
                newCchReferencedDomainName <- peek lpcchReferencedDomainName
                newSid <- mallocForeignPtrBytes (fromIntegral newCbSid)
                allocaBytes ((fromIntegral newCchReferencedDomainName) * sizeOf (undefined :: CWchar)) $ \newRdnBuffer ->
                  go lpSystemName lpAccountName newSid lpcbSid newRdnBuffer lpcchReferencedDomainName lppeUse
              _ -> E.failWith "LookupAccountNameW" $ E.fromDWORD err_code

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

lookupAccountSid :: Maybe T.Text -> Sid -> IO (Maybe LookedUpAccount)
lookupAccountSid systemName sid =
  maybe ($ nullPtr) SH.useAsPtr0 systemName $ \lpSystemName ->
  withSidPtr sid $ \pSid ->
  with 0 $ \lpcchName ->
  with 0 $ \lpcchReferencedDomainName ->
  with (SID_NAME_USE 0) $ \lppeUse ->
    go lpSystemName pSid nullPtr lpcchName nullPtr lpcchReferencedDomainName lppeUse
  where
    go lpSystemName pSid nameBuffer lpcchName rdnBuffer lpcchRdn lppeUse = do
      cchName <- peek lpcchName
      cchRdn <- peek lpcchRdn
      r <- c_LookupAccountSidW lpSystemName pSid nameBuffer lpcchName rdnBuffer lpcchRdn lppeUse
      if r
        then do
          -- -1s are for terminating nulls
          name <- T.fromPtr (castPtr nameBuffer) (fromIntegral cchName - 1)
          rdn <- T.fromPtr (castPtr rdnBuffer) (fromIntegral cchRdn - 1)
          use <- peek lppeUse
          return . Just $ LookedUpAccount sid name rdn use
        else do
          err_code <- getLastError
          case err_code of
            #{const ERROR_NONE_MAPPED} -> return Nothing
            #{const ERROR_INSUFFICIENT_BUFFER} -> do
              newCchName <- peek lpcchName
              newCchRdn <- peek lpcchRdn
              allocaBytes ((fromIntegral newCchName) * sizeOf (undefined :: CWchar)) $ \newNameBuffer ->
                allocaBytes ((fromIntegral newCchRdn) * sizeOf (undefined :: CWchar)) $ \newRdnBuffer ->
                  go lpSystemName pSid newNameBuffer lpcchName newRdnBuffer lpcchRdn lppeUse
            _ -> E.failWith "LookupAccountSidW" $ E.fromDWORD err_code

foreign import WINDOWS_CCONV unsafe "windows.h LookupAccountSidW"
  c_LookupAccountSidW
    :: LPCWSTR -- lpSystemName
    -> PSID -- lpSid
    -> LPWSTR -- lpName
    -> LPDWORD -- cchName
    -> LPWSTR -- lpReferencedDomainName
    -> LPDWORD -- cchReferencedDomainName
    -> PSID_NAME_USE -- peUse
    -> IO BOOL

openProcessToken :: ProcessHandle -> IO HANDLE
openProcessToken handle = alloca $ \pToken -> do
  E.failIfFalse_ "OpenProcessToken" $ c_OpenProcessToken handle #{const TOKEN_QUERY} pToken
  peek pToken

foreign import WINDOWS_CCONV unsafe "windows.h OpenProcessToken"
  c_OpenProcessToken
    :: HANDLE -- ProcessHandle
    -> DWORD -- DesiredAccess
    -> Ptr HANDLE -- TokenHandle
    -> IO BOOL

getProcessUserSid :: ProcessHandle -> IO Sid
getProcessUserSid handle = do
    token <- openProcessToken handle
    go token Nothing 0
  where
    go handle maybeBuf bufSize =
      with 0 $ \pReturnLength ->
      maybe ($ nullPtr) withForeignPtr maybeBuf $ \pBuf -> do
      ret <- c_GetTokenInformation handle #{const TokenUser} pBuf bufSize pReturnLength
      if ret
        then unmarshalAndReturn (fromJust maybeBuf)
        else do
          errValue <- getLastError
          case errValue of
            #{const ERROR_INSUFFICIENT_BUFFER} -> do
              properBufferSize <- peek pReturnLength
              newBuffer <- mallocForeignPtrBytes $ fromIntegral properBufferSize
              go handle (Just newBuffer) properBufferSize
            x ->
              E.failWith "GetTokenInformation" $ E.fromDWORD x
    unmarshalAndReturn buf = return $ Sid $ \act -> withForeignPtr buf $ \pBuf -> do
      pSid <- peek $ pBuf `plusPtr` #{offset TOKEN_USER, User} `plusPtr` #{offset SID_AND_ATTRIBUTES, Sid}
      act pSid

{-# CFILES cbits/HsWin32.c #-}
foreign import ccall "HsWin32.h &HS_Win32Security_CloseHandleFinaliser"
    c_CloseHandleFinaliser :: FunPtr (Ptr a -> IO ())

foreign import WINDOWS_CCONV unsafe "windows.h GetTokenInformation"
  c_GetTokenInformation
    :: HANDLE -- TokenHandle
    -> BYTE -- TokenInformationClass
    -> Ptr () -- TokenInformation
    -> DWORD -- TokenInformationLength
    -> LPDWORD -- ReturnLength
    -> IO BOOL

-- | Wrapper for API GetCurrentProcess() function. This would look better in a
-- System.Win32.Process module, but that one is located in win32 package, which
-- is rather hard to change.
getCurrentProcess :: IO ProcessHandle
getCurrentProcess = c_GetCurrentProcess

foreign import WINDOWS_CCONV unsafe "window.h GetCurrentProcess"
  c_GetCurrentProcess
    :: IO HANDLE
