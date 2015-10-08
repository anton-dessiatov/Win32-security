{-# LANGUAGE CPP, ForeignFunctionInterface, GeneralizedNewtypeDeriving, OverloadedStrings, RankNTypes #-}
module System.Win32.Security.SecurityInfo
  ( SecurityDescriptor

  , SecurityObjectType
  , securityObjectUnknown
  , securityObjectFile
  , securityObjectService
  , securityObjectPrinter
  , securityObjectRegistryKey
  , securityObjectLMShare
  , securityObjectKernelObject
  , securityObjectDSObject
  , securityObjectDSObjectAll
  , securityObjectProviderDefined
  , securityObjectWMIGuid
  , securityObjectRegistryWow6432Key

  , SecurityInformation
  , securityInformationOwner
  , securityInformationGroup
  , securityInformationDacl
  , securityInformationSacl
  , securityInformationAll

  , GetSecurityInfoResult (..)
  , getNamedSecurityInfo
  , SetSecurityInfoAcl (..)
  , setNamedSecurityInfo
  ) where

import Foreign
import System.Win32.Types
import System.Win32.Security
import System.Win32.Security.Sid
import System.Win32.Security.AccessControl
import qualified Data.Text as T
import qualified System.Win32.Error as E -- documentation comments
import qualified System.Win32.Error.Foreign as E
import qualified System.Win32.Security.Helpers as SH

#include <windows.h>
#include <AccCtrl.h>

newtype SecurityDescriptor = SecurityDescriptor (ForeignPtr SECURITY_DESCRIPTOR)

-- | newtype wrapper around Windows SDK SE_OBJECT_TYPE enumeration
newtype SecurityObjectType = SecurityObjectType BYTE
#{enum SecurityObjectType, SecurityObjectType
 , securityObjectUnknown            = SE_UNKNOWN_OBJECT_TYPE
 , securityObjectFile               = SE_FILE_OBJECT
 , securityObjectService            = SE_SERVICE
 , securityObjectPrinter            = SE_PRINTER
 , securityObjectRegistryKey        = SE_REGISTRY_KEY
 , securityObjectLMShare            = SE_LMSHARE
 , securityObjectKernelObject       = SE_KERNEL_OBJECT
 , securityObjectDSObject           = SE_DS_OBJECT
 , securityObjectDSObjectAll        = SE_DS_OBJECT_ALL
 , securityObjectProviderDefined    = SE_PROVIDER_DEFINED_OBJECT
 , securityObjectWMIGuid            = SE_WMIGUID_OBJECT
 , securityObjectRegistryWow6432Key = SE_REGISTRY_WOW64_32KEY
 }

newtype SecurityInformation = SecurityInformation DWORD
  deriving (Bits, Eq)

securityInformationOwner :: SecurityInformation
securityInformationOwner = SecurityInformation oWNER_SECURITY_INFORMATION

securityInformationGroup :: SecurityInformation
securityInformationGroup = SecurityInformation gROUP_SECURITY_INFORMATION

securityInformationDacl :: SecurityInformation
securityInformationDacl = SecurityInformation dACL_SECURITY_INFORMATION

securityInformationSacl :: SecurityInformation
securityInformationSacl = SecurityInformation sACL_SECURITY_INFORMATION

securityInformationAll :: SecurityInformation
securityInformationAll = SecurityInformation $
  oWNER_SECURITY_INFORMATION .|. gROUP_SECURITY_INFORMATION .|.
  dACL_SECURITY_INFORMATION .|. sACL_SECURITY_INFORMATION

foreign import WINDOWS_CCONV unsafe "windows.h GetNamedSecurityInfoW"
  c_GetNamedSecurityInfoW
    :: LPWSTR -- pObjectName
    -> BYTE -- ObjectType
    -> DWORD -- SecurityInformation
    -> Ptr PSID -- ppsidOwner
    -> Ptr PSID -- ppsidGroup
    -> Ptr PACL -- ppDacl
    -> Ptr PACL -- ppSacl
    -> Ptr (Ptr SECURITY_DESCRIPTOR) -- ppSecurityDescriptor
    -> IO DWORD

data GetSecurityInfoResult = GetSecurityInfoResult
  { securityInfoOwner      :: Maybe Sid
  , securityInfoGroup      :: Maybe Sid
  , securityInfoDacl       :: Maybe Acl
  , securityInfoSacl       :: Maybe Acl
  , securityInfoDescriptor :: SecurityDescriptor
  }

getNamedSecurityInfo :: T.Text -> SecurityObjectType -> SecurityInformation
    -> IO GetSecurityInfoResult
    -- ^ This function will throw a 'E.Win32Exception' exception when the
    -- internal Win32 call returns an error condition. Microsoft's
    -- documentation does not list which errors are likely to occur.
getNamedSecurityInfo objectName (SecurityObjectType objectType) (SecurityInformation securityInfo) =
  SH.useAsPtr0 objectName $ \pObjectName ->
  alloca $ \ppSidOwner ->
  alloca $ \ppSidGroup ->
  alloca $ \ppDacl ->
  alloca $ \ppSacl ->
  alloca $ \ppSecurityDescriptor -> do
    E.failUnlessSuccess "GetNamedSecurityInfoW" $
      c_GetNamedSecurityInfoW pObjectName objectType securityInfo ppSidOwner ppSidGroup ppDacl ppSacl ppSecurityDescriptor
    sdPtr <- peek ppSecurityDescriptor
    sd <- newForeignPtr localFreeFinaliser sdPtr
    ownerSid <- if securityInfo .&. oWNER_SECURITY_INFORMATION /= 0
      then do
        pSidOwner <- peek ppSidOwner
        return . Just $ Sid $ \act -> withForeignPtr sd $ \_ -> act pSidOwner
      else
        return Nothing
    groupSid <- if securityInfo .&. gROUP_SECURITY_INFORMATION /= 0
      then do
        pSidGroup <- peek ppSidGroup
        return . Just $ Sid $ \act -> withForeignPtr sd $ \_ -> act pSidGroup
      else
        return Nothing
    dacl <- if securityInfo .&. dACL_SECURITY_INFORMATION /= 0
      then do
        pDacl <- peek ppDacl
        return . Just $ Acl $ \act -> withForeignPtr sd $ \_ -> act pDacl
      else
        return Nothing
    sacl <- if securityInfo .&. sACL_SECURITY_INFORMATION /= 0
      then do
        pSacl <- peek ppSacl
        return . Just $ Acl $ \act -> withForeignPtr sd $ \_ -> act pSacl
      else
        return Nothing
    return GetSecurityInfoResult
      { securityInfoOwner = ownerSid
      , securityInfoGroup = groupSid
      , securityInfoDacl = dacl
      , securityInfoSacl = sacl
      , securityInfoDescriptor = SecurityDescriptor sd
      }

{-# CFILES cbits/Win32Security.c #-}
foreign import ccall "Win32Security.h &HS_Win32Security_LocalFreeFinaliser"
  localFreeFinaliser :: FunPtr (Ptr a -> IO ())

data SetSecurityInfoAcl
  = DontSetAcl
  -- | Set ACL and prevent inheritable ACEs from propagating
  | ProtectedAcl Acl
  -- | Set ACL and allow inheritable ACEs to propagate
  | UnprotectedAcl Acl

setNamedSecurityInfo :: T.Text -> SecurityObjectType -> Maybe Sid -> Maybe Sid -> SetSecurityInfoAcl -> SetSecurityInfoAcl -> IO ()
setNamedSecurityInfo objectName (SecurityObjectType objectType) maybeOwner maybeGroup ssiDacl ssiSacl =
    SH.useAsPtr0 objectName $ \pObjectName ->
    maybe ($ nullPtr) withSidPtr maybeOwner $ \psidOwner ->
    maybe ($ nullPtr) withSidPtr maybeGroup $ \psidGroup ->
    withSecurityInfoAcl ssiDacl $ \pDacl ->
    withSecurityInfoAcl ssiSacl $ \pSacl ->
      let securityInfo = 0
            .|. if psidOwner /= nullPtr then oWNER_SECURITY_INFORMATION else 0
            .|. if psidGroup /= nullPtr then gROUP_SECURITY_INFORMATION else  0
            .|. case ssiDacl of
                  DontSetAcl -> 0
                  ProtectedAcl _ -> dACL_SECURITY_INFORMATION .|. #{const PROTECTED_DACL_SECURITY_INFORMATION}
                  UnprotectedAcl _ -> dACL_SECURITY_INFORMATION
            .|. case ssiSacl of
                  DontSetAcl -> 0
                  ProtectedAcl _ -> sACL_SECURITY_INFORMATION .|. #{const PROTECTED_SACL_SECURITY_INFORMATION}
                  UnprotectedAcl _ -> sACL_SECURITY_INFORMATION
      in E.failUnlessSuccess "SetNamedSecurityInfoW" $
           c_SetNamedSecurityInfoW pObjectName objectType securityInfo psidOwner psidGroup pDacl pSacl
  where
    withSecurityInfoAcl :: SetSecurityInfoAcl -> (Ptr ACL -> IO a) -> IO a
    withSecurityInfoAcl ssia act = case ssia of
      DontSetAcl -> act $ nullPtr
      ProtectedAcl x -> withAclPtr x act
      UnprotectedAcl x -> withAclPtr x act

-- | Official prototype:
-- DWORD WINAPI SetNamedSecurityInfo(
--   _In_      LPTSTR pObjectName,
--   _In_      SE_OBJECT_TYPE ObjectType,
--   _In_      SECURITY_INFORMATION SecurityInfo,
--   _In_opt_  PSID psidOwner,
--   _In_opt_  PSID psidGroup,
--   _In_opt_  PACL pDacl,
--   _In_opt_  PACL pSacl
-- );
foreign import WINDOWS_CCONV "windows.h SetNamedSecurityInfoW"
  c_SetNamedSecurityInfoW
    :: LPWSTR -- pObjectName
    -> BYTE -- ObjectType
    -> DWORD -- SecurityInfo
    -> PSID -- psidOwner
    -> PSID -- psidGroup
    -> PACL -- pDacl
    -> PACL -- pSacl
    -> IO DWORD
