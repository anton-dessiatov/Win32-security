{-# LANGUAGE CPP, EmptyDataDecls, ForeignFunctionInterface,
             GeneralizedNewtypeDeriving, PatternSynonyms #-}
module System.Win32.Security.Sspi.Internal where

import Data.Bits
import Foreign
import Foreign.C.Types
import System.Win32.Types
import System.Win32.Cryptography.Types
import System.Win32.Security.Helpers
import Text.Printf

#define SECURITY_WIN32
#include <windows.h>
#include <Security.h>
#include <Credssp.h>
#include <schannel.h>

data CredHandle

instance Storable CredHandle where
  sizeOf _ = #{size CredHandle}
  alignment _ = alignment (undefined :: CInt)
  poke _ _ = undefined
  peek _ = undefined

type PCredHandle = Ptr CredHandle

data TimeStamp

instance Storable TimeStamp where
  sizeOf _ = #{size TimeStamp}
  alignment _ = alignment (undefined :: CInt)
  poke _ _ = undefined
  peek _ = undefined

type PTimeStamp = Ptr TimeStamp

data CtxtHandle

instance Storable CtxtHandle where
  sizeOf _ = #{size CtxtHandle}
  alignment _ = alignment (undefined :: CInt)
  poke _ _ = undefined
  peek _ = undefined

type PCtxtHandle = Ptr CtxtHandle

type SecurityStatus = #{type SECURITY_STATUS}

--  SECURITY_STATUS SEC_ENTRY AcquireCredentialsHandleW(
--    _In_opt_   LPWSTR         *pszPrincipal,
--    _In_       LPWSTR         *pszPackage,
--    _In_       unsigned long  fCredentialUse,
--    _In_opt_   void           *pvLogonID,
--    _In_opt_   void           *pAuthData,
--    _In_opt_   SEC_GET_KEY_FN pGetKeyFn,
--    _Reserved_ void           *pvGetKeyArgument,
--    _Out_      PCredHandle    phCredential,
--    _Out_opt_  PTimeStamp     ptsExpiry
--  );
foreign import WINDOWS_CCONV "windows.h AcquireCredentialsHandleW"
  c_AcquireCredentialsHandle
    :: LPWSTR -- pszPrincipal
    -> LPWSTR -- pszPackage
    -> CULong -- fCredentialUse
    -> Ptr () -- pvLogonID
    -> Ptr () -- pAuthData
    -> Ptr () -- pGetKeyFn
    -> Ptr () -- pvGetKeyArgument
    -> PCredHandle -- phCredential
    -> PTimeStamp -- ptsExpiry
    -> IO SecurityStatus

newtype CredentialUse = CredentialUse { unCredentialUse :: CULong }
pattern SECPKG_CRED_INBOUND = CredentialUse #{const SECPKG_CRED_INBOUND}
pattern SECPKG_CRED_OUTBOUND = CredentialUse #{const SECPKG_CRED_OUTBOUND}

--  SECURITY_STATUS SEC_Entry FreeCredentialsHandle(
--    _In_ PCredHandle phCredential
--  );
foreign import WINDOWS_CCONV "windows.h FreeCredentialsHandle"
  c_FreeCredentialsHandle
    :: PCredHandle -- phCredential
    -> IO SecurityStatus

newtype AuthIdentityFlags = AuthIdentityFlags { unAuthIdentityFlags :: CULong }
  deriving (Eq, Num, Storable)

pattern SEC_WINNT_AUTH_IDENTITY_ANSI = #{const SEC_WINNT_AUTH_IDENTITY_ANSI}
pattern SEC_WINNT_AUTH_IDENTITY_UNICODE = #{const SEC_WINNT_AUTH_IDENTITY_UNICODE}

authIdentityFlagsNames :: [(AuthIdentityFlags, String)]
authIdentityFlagsNames =
  [ (SEC_WINNT_AUTH_IDENTITY_ANSI, "SEC_WINNT_AUTH_IDENTITY_ANSI")
  , (SEC_WINNT_AUTH_IDENTITY_UNICODE, "SEC_WINNT_AUTH_IDENTITY_UNICODE")
  ]

instance Show AuthIdentityFlags where
  show x = printf "AuthIdentityFlags{ %s }" (pickName authIdentityFlagsNames unAuthIdentityFlags x)

data SEC_WINNT_AUTH_IDENTITY = SEC_WINNT_AUTH_IDENTITY
  { user           :: Ptr CUShort
  , userLength     :: CULong
  , domain         :: Ptr CUShort
  , domainLength   :: CULong
  , password       :: Ptr CUShort
  , passwordLength :: CULong
  , flags          :: AuthIdentityFlags
  } deriving (Show)

instance Storable SEC_WINNT_AUTH_IDENTITY where
  sizeOf _ = #{size SEC_WINNT_AUTH_IDENTITY}
  alignment _ = alignment (undefined :: CInt)
  poke p x = do
    #{poke SEC_WINNT_AUTH_IDENTITY, User} p $ user x
    #{poke SEC_WINNT_AUTH_IDENTITY, UserLength} p $ userLength x
    #{poke SEC_WINNT_AUTH_IDENTITY, Domain} p $ domain x
    #{poke SEC_WINNT_AUTH_IDENTITY, DomainLength} p $ domainLength x
    #{poke SEC_WINNT_AUTH_IDENTITY, Password} p $ password x
    #{poke SEC_WINNT_AUTH_IDENTITY, PasswordLength} p $ passwordLength x
    #{poke SEC_WINNT_AUTH_IDENTITY, Flags} p $ flags x
  peek p = SEC_WINNT_AUTH_IDENTITY
    <$> #{peek SEC_WINNT_AUTH_IDENTITY, User} p
    <*> #{peek SEC_WINNT_AUTH_IDENTITY, UserLength} p
    <*> #{peek SEC_WINNT_AUTH_IDENTITY, Domain} p
    <*> #{peek SEC_WINNT_AUTH_IDENTITY, DomainLength} p
    <*> #{peek SEC_WINNT_AUTH_IDENTITY, Password} p
    <*> #{peek SEC_WINNT_AUTH_IDENTITY, PasswordLength} p
    <*> #{peek SEC_WINNT_AUTH_IDENTITY, Flags} p

newtype CREDSSP_SUBMIT_TYPE = CREDSSP_SUBMIT_TYPE { unCredSSPSubmitType :: CChar }
  deriving (Eq, Num, Storable)

pattern CredsspPasswordCreds = CREDSSP_SUBMIT_TYPE #{const CredsspPasswordCreds}
pattern CredsspSchannelCreds = CREDSSP_SUBMIT_TYPE #{const CredsspSchannelCreds}
pattern CredsspCertificateCreds = CREDSSP_SUBMIT_TYPE #{const CredsspCertificateCreds}
pattern CredsspSubmitBufferBoth = CREDSSP_SUBMIT_TYPE #{const CredsspSubmitBufferBoth}
pattern CredsspSubmitBufferBothOld = CREDSSP_SUBMIT_TYPE #{const CredsspSubmitBufferBothOld}

cREDSSP_SUBMIT_TYPENames :: [(CREDSSP_SUBMIT_TYPE, String)]
cREDSSP_SUBMIT_TYPENames =
  [ (CredsspPasswordCreds, "CredsspPasswordCreds")
  , (CredsspSchannelCreds, "CredsspSchannelCreds")
  , (CredsspCertificateCreds, "CredsspCertificateCreds")
  , (CredsspSubmitBufferBoth, "CredsspSubmitBufferBoth")
  , (CredsspSubmitBufferBothOld, "CredsspSubmitBufferBothOld")
  ]

instance Show CREDSSP_SUBMIT_TYPE where
  show x = printf "CREDSSP_SUBMIT_TYPE{ %s }" (pickName cREDSSP_SUBMIT_TYPENames unCredSSPSubmitType x)

data CREDSSP_CRED = CREDSSP_CRED
  { credType      :: CREDSSP_SUBMIT_TYPE
  , pSchannelCred :: Ptr ()
  , pSpnegoCred   :: Ptr ()
  }

instance Storable CREDSSP_CRED where
  sizeOf _ = #{size CREDSSP_CRED}
  alignment _ = alignment (undefined :: CInt)
  poke p x = do
    #{poke CREDSSP_CRED, Type} p $ credType x
    #{poke CREDSSP_CRED, pSchannelCred} p $ pSchannelCred x
    #{poke CREDSSP_CRED, pSpnegoCred} p $ pSpnegoCred x
  peek p = CREDSSP_CRED
    <$> #{peek CREDSSP_CRED, Type} p
    <*> #{peek CREDSSP_CRED, pSchannelCred} p
    <*> #{peek CREDSSP_CRED, pSpnegoCred} p

-- | Direct representation of Windows SecBuffer structure.
data SecBuffer = SecBuffer
  { cbBuffer   :: CULong
  , bufferType :: SecBufferType
  , pvBuffer   :: Ptr ()
  } deriving (Show)

instance Storable SecBuffer where
  sizeOf _ = #{size SecBuffer}
  alignment _ = alignment (undefined :: CInt)
  poke p x = do
    #{poke SecBuffer, cbBuffer} p $ cbBuffer x
    #{poke SecBuffer, BufferType} p $ bufferType x
    #{poke SecBuffer, pvBuffer} p $ pvBuffer x
  peek p = SecBuffer
    <$> #{peek SecBuffer, cbBuffer} p
    <*> #{peek SecBuffer, BufferType} p
    <*> #{peek SecBuffer, pvBuffer} p

type PSecBuffer = Ptr SecBuffer

newtype SecBufferType = SecBufferType { unSecBufferType :: CULong }
  deriving (Bits, Eq, Storable)

pattern SECBUFFER_ALERT = SecBufferType 0x11
pattern SECBUFFER_ATTRMASK = SecBufferType 0xF0000000
pattern SECBUFFER_CHANNEL_BINDINGS = SecBufferType 0xE
pattern SECBUFFER_CHANGE_PASS_RESPONSE = SecBufferType 0xF
pattern SECBUFFER_DATA = SecBufferType 0x1
pattern SECBUFFER_EMPTY = SecBufferType 0x0
pattern SECBUFFER_EXTRA = SecBufferType 0x5
pattern SECBUFFER_MECHLIST = SecBufferType 0xB
pattern SECBUFFER_MECHLIST_SIGNATURE = SecBufferType 0xC
pattern SECBUFFER_MISSING = SecBufferType 0x4
pattern SECBUFFER_PKG_PARAMS = SecBufferType 0x3
pattern SECBUFFER_STREAM_HEADER = SecBufferType 0x7
pattern SECBUFFER_STREAM_TRAILER = SecBufferType 0x6
pattern SECBUFFER_TARGET = SecBufferType 0xD
pattern SECBUFFER_TARGET_HOST = SecBufferType 0x10
pattern SECBUFFER_TOKEN = SecBufferType 0x2
pattern SECBUFFER_APPLICATION_PROTOCOLS = SecBufferType 18
pattern SECBUFFER_READONLY = SecBufferType 0x80000000
pattern SECBUFFER_READONLY_WITH_CHECKSUM = SecBufferType 0x10000000

secBufferTypeNames :: [(SecBufferType, String)]
secBufferTypeNames =
  [ (SECBUFFER_ALERT, "SECBUFFER_ALERT")
  , (SECBUFFER_CHANNEL_BINDINGS, "SECBUFFER_CHANNEL_BINDINGS")
  , (SECBUFFER_CHANGE_PASS_RESPONSE, "SECBUFFER_CHANGE_PASS_RESPONSE")
  , (SECBUFFER_DATA, "SECBUFFER_DATA")
  , (SECBUFFER_EMPTY, "SECBUFFER_EMPTY")
  , (SECBUFFER_EXTRA, "SECBUFFER_EXTRA")
  , (SECBUFFER_MECHLIST, "SECBUFFER_MECHLIST")
  , (SECBUFFER_MECHLIST_SIGNATURE, "SECBUFFER_MECHLIST_SIGNATURE")
  , (SECBUFFER_MISSING, "SECBUFFER_MISSING")
  , (SECBUFFER_PKG_PARAMS, "SECBUFFER_PKG_PARAMS")
  , (SECBUFFER_STREAM_HEADER, "SECBUFFER_STREAM_HEADER")
  , (SECBUFFER_STREAM_TRAILER, "SECBUFFER_STREAM_TRAILER")
  , (SECBUFFER_TARGET, "SECBUFFER_TARGET")
  , (SECBUFFER_TARGET_HOST, "SECBUFFER_TARGET_HOST")
  , (SECBUFFER_TOKEN, "SECBUFFER_TOKEN")
  , (SECBUFFER_APPLICATION_PROTOCOLS, "SECBUFFER_APPLICATION_PROTOCOLS")
  , (SECBUFFER_READONLY, "SECBUFFER_READONLY")
  , (SECBUFFER_READONLY_WITH_CHECKSUM, "SECBUFFER_READONLY_WITH_CHECKSUM")
  ]

instance Show SecBufferType where
  show x = printf "SecBufferType{ %s }" (parseEnumWithFlags secBufferTypeNames [SECBUFFER_READONLY, SECBUFFER_READONLY_WITH_CHECKSUM] unSecBufferType x)

data RawSecBufferDesc = RawSecBufferDesc
  { ulVersion :: CULong
  , cBuffers  :: CULong
  , pBuffers  :: PSecBuffer
  }

instance Storable RawSecBufferDesc where
  sizeOf _ = #{size SecBufferDesc}
  alignment _ = alignment (undefined :: CInt)
  poke p x = do
    #{poke SecBufferDesc, ulVersion} p $ ulVersion x
    #{poke SecBufferDesc, cBuffers} p $ cBuffers x
    #{poke SecBufferDesc, pBuffers} p $ pBuffers x
  peek p = RawSecBufferDesc
    <$> #{peek SecBufferDesc, ulVersion} p
    <*> #{peek SecBufferDesc, cBuffers} p
    <*> #{peek SecBufferDesc, pBuffers} p

pattern SECBUFFER_VERSION = #{const SECBUFFER_VERSION}

type PRawSecBufferDesc = Ptr RawSecBufferDesc

newtype IscContextReq = IscContextReq { unIscContextReq :: CULong }
  deriving (Bits, Eq)

pattern ISC_REQ_ALLOCATE_MEMORY = IscContextReq #{const ISC_REQ_ALLOCATE_MEMORY}
pattern ISC_REQ_CONNECTION = IscContextReq #{const ISC_REQ_CONNECTION}
pattern ISC_REQ_CONFIDENTIALITY = IscContextReq #{const ISC_REQ_CONFIDENTIALITY}
pattern ISC_REQ_USE_SESSION_KEY = IscContextReq #{const ISC_REQ_USE_SESSION_KEY}
pattern ISC_REQ_EXTENDED_ERROR = IscContextReq #{const ISC_REQ_EXTENDED_ERROR}
pattern ISC_REQ_MANUAL_CRED_VALIDATION = IscContextReq #{const ISC_REQ_MANUAL_CRED_VALIDATION}
pattern ISC_REQ_SEQUENCE_DETECT = IscContextReq #{const ISC_REQ_SEQUENCE_DETECT}
pattern ISC_REQ_STREAM = IscContextReq #{const ISC_REQ_STREAM}
pattern ISC_REQ_USE_SUPPLIED_CREDS = IscContextReq #{const ISC_REQ_USE_SUPPLIED_CREDS}
pattern ISC_REQ_DELEGATE = IscContextReq #{const ISC_REQ_DELEGATE}
pattern ISC_REQ_MUTUAL_AUTH = IscContextReq #{const ISC_REQ_MUTUAL_AUTH}

iscContextReqNames :: [(IscContextReq, String)]
iscContextReqNames =
  [ (ISC_REQ_ALLOCATE_MEMORY, "ISC_REQ_ALLOCATE_MEMORY")
  , (ISC_REQ_CONNECTION, "ISC_REQ_CONNECTION")
  , (ISC_REQ_CONFIDENTIALITY, "ISC_REQ_CONFIDENTIALITY")
  , (ISC_REQ_USE_SESSION_KEY, "ISC_REQ_USE_SESSION_KEY")
  , (ISC_REQ_EXTENDED_ERROR, "ISC_REQ_EXTENDED_ERROR")
  , (ISC_REQ_MANUAL_CRED_VALIDATION, "ISC_REQ_MANUAL_CRED_VALIDATION")
  , (ISC_REQ_SEQUENCE_DETECT, "ISC_REQ_SEQUENCE_DETECT")
  , (ISC_REQ_STREAM, "ISC_REQ_STREAM")
  , (ISC_REQ_USE_SUPPLIED_CREDS, "ISC_REQ_USE_SUPPLIED_CREDS")
  , (ISC_REQ_DELEGATE, "ISC_REQ_DELEGATE")
  , (ISC_REQ_MUTUAL_AUTH, "ISC_REQ_MUTUAL_AUTH")
  ]

instance Show IscContextReq where
  show x = printf "IscContextReq{ %s }" (parseBitFlags iscContextReqNames unIscContextReq x)

newtype TargetDataRep = TargetDataRep { unTargetDataRep :: CULong }
  deriving (Eq)

pattern SECURITY_NATIVE_DREP = TargetDataRep #{const SECURITY_NATIVE_DREP}
pattern SECURITY_NETWORK_DREP = TargetDataRep #{const SECURITY_NETWORK_DREP}

targetDataRepNames :: [(TargetDataRep, String)]
targetDataRepNames =
  [ (SECURITY_NATIVE_DREP, "SECURITY_NATIVE_DREP")
  , (SECURITY_NETWORK_DREP, "SECURITY_NETWORK_DREP")
  ]

instance Show TargetDataRep where
  show x = printf "TargetDataRep{ %s }" (pickName targetDataRepNames unTargetDataRep x)

newtype IscRetContextAttr = IscRetContextAttr { unIscRetContextAttr :: CULong }
  deriving (Bits, Eq)

pattern ISC_RET_DELEGATE = IscRetContextAttr 0x00000001
pattern ISC_RET_MUTUAL_AUTH = IscRetContextAttr 0x00000002
pattern ISC_RET_REPLAY_DETECT = IscRetContextAttr 0x00000004
pattern ISC_RET_SEQUENCE_DETECT = IscRetContextAttr 0x00000008
pattern ISC_RET_CONFIDENTIALITY = IscRetContextAttr 0x00000010
pattern ISC_RET_USE_SESSION_KEY = IscRetContextAttr 0x00000020
pattern ISC_RET_USED_COLLECTED_CREDS = IscRetContextAttr 0x00000040
pattern ISC_RET_USED_SUPPLIED_CREDS = IscRetContextAttr 0x00000080
pattern ISC_RET_ALLOCATED_MEMORY = IscRetContextAttr 0x00000100
pattern ISC_RET_USED_DCE_STYLE = IscRetContextAttr 0x00000200
pattern ISC_RET_DATAGRAM = IscRetContextAttr 0x00000400
pattern ISC_RET_CONNECTION = IscRetContextAttr 0x00000800
pattern ISC_RET_INTERMEDIATE_RETURN = IscRetContextAttr 0x00001000
pattern ISC_RET_CALL_LEVEL = IscRetContextAttr 0x00002000
pattern ISC_RET_EXTENDED_ERROR = IscRetContextAttr 0x00004000
pattern ISC_RET_STREAM = IscRetContextAttr 0x00008000
pattern ISC_RET_INTEGRITY = IscRetContextAttr 0x00010000
pattern ISC_RET_IDENTIFY = IscRetContextAttr 0x00020000
pattern ISC_RET_NULL_SESSION = IscRetContextAttr 0x00040000
pattern ISC_RET_FRAGMENT_ONLY = IscRetContextAttr 0x00200000

iscRetContextAttrNames :: [(IscRetContextAttr, String)]
iscRetContextAttrNames =
  [ (ISC_RET_DELEGATE, "ISC_RET_DELEGATE")
  , (ISC_RET_MUTUAL_AUTH, "ISC_RET_MUTUAL_AUTH")
  , (ISC_RET_REPLAY_DETECT, "ISC_RET_REPLAY_DETECT")
  , (ISC_RET_SEQUENCE_DETECT, "ISC_RET_SEQUENCE_DETECT")
  , (ISC_RET_CONFIDENTIALITY, "ISC_RET_CONFIDENTIALITY")
  , (ISC_RET_USE_SESSION_KEY, "ISC_RET_USE_SESSION_KEY")
  , (ISC_RET_USED_COLLECTED_CREDS, "ISC_RET_USED_COLLECTED_CREDS")
  , (ISC_RET_USED_SUPPLIED_CREDS, "ISC_RET_USED_SUPPLIED_CREDS")
  , (ISC_RET_ALLOCATED_MEMORY, "ISC_RET_ALLOCATED_MEMORY")
  , (ISC_RET_USED_DCE_STYLE, "ISC_RET_USED_DCE_STYLE")
  , (ISC_RET_DATAGRAM, "ISC_RET_DATAGRAM")
  , (ISC_RET_CONNECTION, "ISC_RET_CONNECTION")
  , (ISC_RET_INTERMEDIATE_RETURN, "ISC_RET_INTERMEDIATE_RETURN")
  , (ISC_RET_CALL_LEVEL, "ISC_RET_CALL_LEVEL")
  , (ISC_RET_EXTENDED_ERROR, "ISC_RET_EXTENDED_ERROR")
  , (ISC_RET_STREAM, "ISC_RET_STREAM")
  , (ISC_RET_INTEGRITY, "ISC_RET_INTEGRITY")
  , (ISC_RET_IDENTIFY, "ISC_RET_IDENTIFY")
  , (ISC_RET_NULL_SESSION, "ISC_RET_NULL_SESSION")
  , (ISC_RET_FRAGMENT_ONLY, "ISC_RET_FRAGMENT_ONLY")
  ]

instance Show IscRetContextAttr where
  show x = printf "IscRetContextAttr{ %s }" (parseBitFlags iscRetContextAttrNames unIscRetContextAttr x)

-- SECURITY_STATUS SEC_ENTRY InitializeSecurityContext(
--   _In_opt_    PCredHandle    phCredential,
--   _In_opt_    PCtxtHandle    phContext,
--   _In_opt_    SEC_CHAR       *pszTargetName,
--   _In_        unsigned long  fContextReq,
--   _Reserved_  unsigned long  Reserved1,
--   _In_        unsigned long  TargetDataRep,
--   _Inout_opt_ PSecBufferDesc pInput,
--   _In_        unsigned long  Reserved2,
--   _Inout_opt_ PCtxtHandle    phNewContext,
--   _Out_opt_   PSecBufferDesc pOutput,
--   _Out_       unsigned long  *pfContextAttr,
--   _Out_opt_   PTimeStamp     ptsExpiry
-- );
foreign import WINDOWS_CCONV "windows.h InitializeSecurityContextW"
  c_InitializeSecurityContext
    :: PCredHandle -- phCredential
    -> PCtxtHandle -- phContext
    -> LPWSTR -- pszTargetName
    -> CULong -- fContextReq
    -> CULong -- Reserved1
    -> CULong -- TargetDataRep
    -> PRawSecBufferDesc -- pInput
    -> CULong -- Reserved2
    -> PCtxtHandle -- phNewContext
    -> PRawSecBufferDesc -- pOutput
    -> Ptr CULong -- pfContextAttr
    -> PTimeStamp -- ptsExpiry
    -> IO SecurityStatus

pattern SEC_E_INCOMPLETE_MESSAGE = #{const SEC_E_INCOMPLETE_MESSAGE}
pattern SEC_E_OK = #{const SEC_E_OK}
pattern SEC_I_COMPLETE_AND_CONTINUE = #{const SEC_I_COMPLETE_AND_CONTINUE}
pattern SEC_I_COMPLETE_NEEDED = #{const SEC_I_COMPLETE_NEEDED}
pattern SEC_I_CONTINUE_NEEDED = #{const SEC_I_CONTINUE_NEEDED}
pattern SEC_I_INCOMPLETE_CREDENTIALS = #{const SEC_I_INCOMPLETE_CREDENTIALS}

-- SECURITY_STATUS SEC_Entry DeleteSecurityContext(
--   _In_ PCtxtHandle phContext
-- );
foreign import WINDOWS_CCONV "windows.h DeleteSecurityContext"
  c_DeleteSecurityContext
    :: PCtxtHandle -- phContext
    -> IO SecurityStatus

newtype AscContextReq = AscContextReq { unAscContextReq :: CULong }
  deriving (Bits, Eq)

pattern ASC_REQ_ALLOCATE_MEMORY = AscContextReq #{const ASC_REQ_ALLOCATE_MEMORY}
pattern ASC_REQ_CONNECTION = AscContextReq #{const ASC_REQ_CONNECTION}
pattern ASC_REQ_DELEGATE = AscContextReq #{const ASC_REQ_DELEGATE}
pattern ASC_REQ_EXTENDED_ERROR = AscContextReq #{const ASC_REQ_EXTENDED_ERROR}
pattern ASC_REQ_REPLAY_DETECT = AscContextReq #{const ASC_REQ_REPLAY_DETECT}
pattern ASC_REQ_SEQUENCE_DETECT = AscContextReq #{const ASC_REQ_SEQUENCE_DETECT}
pattern ASC_REQ_STREAM = AscContextReq #{const ASC_REQ_STREAM}

ascContextReqNames :: [(AscContextReq, String)]
ascContextReqNames =
  [ (ASC_REQ_ALLOCATE_MEMORY, "ASC_REQ_ALLOCATE_MEMORY")
  , (ASC_REQ_CONNECTION, "ASC_REQ_CONNECTION")
  , (ASC_REQ_DELEGATE, "ASC_REQ_DELEGATE")
  , (ASC_REQ_EXTENDED_ERROR, "ASC_REQ_EXTENDED_ERROR")
  , (ASC_REQ_REPLAY_DETECT, "ASC_REQ_REPLAY_DETECT")
  , (ASC_REQ_SEQUENCE_DETECT, "ASC_REQ_SEQUENCE_DETECT")
  , (ASC_REQ_STREAM, "ASC_REQ_STREAM")
  ]

instance Show AscContextReq where
  show x = printf "AscContextReq{ %s }" (parseBitFlags ascContextReqNames unAscContextReq x)

newtype AscRetContextAttr = AscRetContextAttr { unAscRetContextAttr :: CULong }
  deriving (Bits, Eq)

pattern ASC_RET_DELEGATE = AscRetContextAttr 0x00000001
pattern ASC_RET_MUTUAL_AUTH = AscRetContextAttr 0x00000002
pattern ASC_RET_REPLAY_DETECT = AscRetContextAttr 0x00000004
pattern ASC_RET_SEQUENCE_DETECT = AscRetContextAttr 0x00000008
pattern ASC_RET_CONFIDENTIALITY = AscRetContextAttr 0x00000010
pattern ASC_RET_USE_SESSION_KEY = AscRetContextAttr 0x00000020
pattern ASC_RET_SESSION_TICKET = AscRetContextAttr 0x00000040
pattern ASC_RET_ALLOCATED_MEMORY = AscRetContextAttr 0x00000100
pattern ASC_RET_USED_DCE_STYLE = AscRetContextAttr 0x00000200
pattern ASC_RET_DATAGRAM = AscRetContextAttr 0x00000400
pattern ASC_RET_CONNECTION = AscRetContextAttr 0x00000800
pattern ASC_RET_CALL_LEVEL = AscRetContextAttr 0x00002000
pattern ASC_RET_THIRD_LEG_FAILED = AscRetContextAttr 0x00004000
pattern ASC_RET_EXTENDED_ERROR = AscRetContextAttr 0x00008000
pattern ASC_RET_STREAM = AscRetContextAttr 0x00010000
pattern ASC_RET_INTEGRITY = AscRetContextAttr 0x00020000
pattern ASC_RET_LICENSING = AscRetContextAttr 0x00040000
pattern ASC_RET_IDENTIFY = AscRetContextAttr 0x00080000
pattern ASC_RET_NULL_SESSION = AscRetContextAttr 0x00100000
pattern ASC_RET_ALLOW_NON_USER_LOGONS = AscRetContextAttr 0x00200000
pattern ASC_RET_ALLOW_CONTEXT_REPLAY = AscRetContextAttr 0x00400000
pattern ASC_RET_FRAGMENT_ONLY = AscRetContextAttr 0x00800000
pattern ASC_RET_NO_TOKEN = AscRetContextAttr 0x01000000
pattern ASC_RET_NO_ADDITIONAL_TOKEN = AscRetContextAttr 0x02000000

ascRetContextAttrNames :: [(AscRetContextAttr, String)]
ascRetContextAttrNames =
  [ (ASC_RET_DELEGATE, "ASC_RET_DELEGATE")
  , (ASC_RET_MUTUAL_AUTH, "ASC_RET_MUTUAL_AUTH")
  , (ASC_RET_REPLAY_DETECT, "ASC_RET_REPLAY_DETECT")
  , (ASC_RET_SEQUENCE_DETECT, "ASC_RET_SEQUENCE_DETECT")
  , (ASC_RET_CONFIDENTIALITY, "ASC_RET_CONFIDENTIALITY")
  , (ASC_RET_USE_SESSION_KEY, "ASC_RET_USE_SESSION_KEY")
  , (ASC_RET_SESSION_TICKET, "ASC_RET_SESSION_TICKET")
  , (ASC_RET_ALLOCATED_MEMORY, "ASC_RET_ALLOCATED_MEMORY")
  , (ASC_RET_USED_DCE_STYLE, "ASC_RET_USED_DCE_STYLE")
  , (ASC_RET_DATAGRAM, "ASC_RET_DATAGRAM")
  , (ASC_RET_CONNECTION, "ASC_RET_CONNECTION")
  , (ASC_RET_CALL_LEVEL, "ASC_RET_CALL_LEVEL")
  , (ASC_RET_THIRD_LEG_FAILED, "ASC_RET_THIRD_LEG_FAILED")
  , (ASC_RET_EXTENDED_ERROR, "ASC_RET_EXTENDED_ERROR")
  , (ASC_RET_STREAM, "ASC_RET_STREAM")
  , (ASC_RET_INTEGRITY, "ASC_RET_INTEGRITY")
  , (ASC_RET_LICENSING, "ASC_RET_LICENSING")
  , (ASC_RET_IDENTIFY, "ASC_RET_IDENTIFY")
  , (ASC_RET_NULL_SESSION, "ASC_RET_NULL_SESSION")
  , (ASC_RET_ALLOW_NON_USER_LOGONS, "ASC_RET_ALLOW_NON_USER_LOGONS")
  , (ASC_RET_ALLOW_CONTEXT_REPLAY, "ASC_RET_ALLOW_CONTEXT_REPLAY")
  , (ASC_RET_FRAGMENT_ONLY, "ASC_RET_FRAGMENT_ONLY")
  , (ASC_RET_NO_TOKEN, "ASC_RET_NO_TOKEN")
  , (ASC_RET_NO_ADDITIONAL_TOKEN, "ASC_RET_NO_ADDITIONAL_TOKEN")
  ]

instance Show AscRetContextAttr where
  show x = printf "AscRetContextAttr{ %s }" (parseBitFlags ascRetContextAttrNames unAscRetContextAttr x)

-- SECURITY_STATUS SEC_ENTRY AcceptSecurityContext(
--   _In_opt_    PCredHandle    phCredential,
--   _In_opt_    PCtxtHandle    phContext,
--   _In_opt_    PSecBufferDesc pInput,
--   _In_        unsigned long  fContextReq,
--   _In_        unsigned long  TargetDataRep,
--   _Inout_opt_ PCtxtHandle    phNewContext,
--   _Inout_opt_ PSecBufferDesc pOutput,
--   _Out_       unsigned long  *pfContextAttr,
--   _Out_opt_   PTimeStamp     ptsExpiry
-- );
foreign import WINDOWS_CCONV "windows.h AcceptSecurityContext"
  c_AcceptSecurityContext
    :: PCredHandle -- phCredential
    -> PCtxtHandle -- phContext
    -> PRawSecBufferDesc -- pInput
    -> CULong -- fContextReq
    -> CULong -- TargetDataRep
    -> PCtxtHandle -- phNewContext
    -> PRawSecBufferDesc -- pOutput
    -> Ptr CULong -- pfContextAttr
    -> PTimeStamp -- ptsExpiry
    -> IO SecurityStatus

newtype QOP = QOP { unQOP :: CULong }
  deriving (Bits, Eq)

pattern SECQOP_WRAP_NO_ENCRYPT = QOP #{const SECQOP_WRAP_NO_ENCRYPT}

-- SECURITY_STATUS SEC_Entry EncryptMessage(
--   _In_    PCtxtHandle    phContext,
--   _In_    ULONG          fQOP,
--   _Inout_ PSecBufferDesc pMessage,
--   _In_    ULONG          MessageSeqNo
-- );
foreign import WINDOWS_CCONV "windows.h EncryptMessage"
  c_EncryptMessage
    :: PCtxtHandle -- phContext
    -> CULong -- fQOP
    -> PRawSecBufferDesc -- pMessage
    -> CULong -- MessageSeqNo
    -> IO SecurityStatus

-- SECURITY_STATUS SEC_Entry DecryptMessage(
--   _In_    PCtxtHandle    phContext,
--   _Inout_ PSecBufferDesc pMessage,
--   _In_    ULONG          MessageSeqNo,
--   _Out_   PULONG         pfQOP
-- );
foreign import WINDOWS_CCONV "windows.h DecryptMessage"
  c_DecryptMessage
    :: PCtxtHandle -- phContext
    -> PRawSecBufferDesc -- pMessage
    -> CULong -- MessageSeqNo
    -> Ptr CULong -- pfQOP
    -> IO SecurityStatus

newtype SecPkgAttr = SecPkgAttr { unSecPkgAttr :: CULong }

-- pattern SECPKG_ATTR_C_ACCESS_TOKEN = SecPkgAttr #{const SECPKG_ATTR_C_ACCESS_TOKEN}
pattern SECPKG_ATTR_C_FULL_ACCESS_TOKEN = SecPkgAttr 0x80000082
pattern SECPKG_ATTR_CERT_TRUST_STATUS = SecPkgAttr 0x80000084
pattern SECPKG_ATTR_CREDS = SecPkgAttr 0x80000080
pattern SECPKG_ATTR_CREDS_2 = SecPkgAttr 0x80000086
pattern SECPKG_ATTR_NEGOTIATION_PACKAGE = SecPkgAttr 0x80000081
pattern SECPKG_ATTR_PACKAGE_INFO = SecPkgAttr 10
pattern SECPKG_ATTR_SERVER_AUTH_FLAGS = SecPkgAttr 0x80000083
pattern SECPKG_ATTR_SIZES = SecPkgAttr 0
pattern SECPKG_ATTR_SUBJECT_SECURITY_ATTRIBUTES = SecPkgAttr 128

-- SECURITY_STATUS SEC_ENTRY QueryContextAttributes(
--   _In_  PCtxtHandle phContext,
--   _In_  ULONG       ulAttribute,
--   _Out_ void        *pBuffer
-- );
foreign import WINDOWS_CCONV "windows.h QueryContextAttributesW"
  c_QueryContextAttributes
    :: PCtxtHandle -- phContext
    -> CULong -- ulAttribute
    -> Ptr () -- pBuffer
    -> IO SecurityStatus

newtype SecPkgCapabilities = SecPkgCapabilities { unSecPkgCapabilities :: CULong }
  deriving (Eq, Bits)

pattern SECPKG_FLAG_INTEGRITY = SecPkgCapabilities #{const SECPKG_FLAG_INTEGRITY}
pattern SECPKG_FLAG_PRIVACY = SecPkgCapabilities #{const SECPKG_FLAG_PRIVACY}
pattern SECPKG_FLAG_TOKEN_ONLY = SecPkgCapabilities #{const SECPKG_FLAG_TOKEN_ONLY}
pattern SECPKG_FLAG_DATAGRAM = SecPkgCapabilities #{const SECPKG_FLAG_DATAGRAM}
pattern SECPKG_FLAG_CONNECTION = SecPkgCapabilities #{const SECPKG_FLAG_CONNECTION}
pattern SECPKG_FLAG_MULTI_REQUIRED = SecPkgCapabilities #{const SECPKG_FLAG_MULTI_REQUIRED}
pattern SECPKG_FLAG_CLIENT_ONLY = SecPkgCapabilities #{const SECPKG_FLAG_CLIENT_ONLY}
pattern SECPKG_FLAG_EXTENDED_ERROR = SecPkgCapabilities #{const SECPKG_FLAG_EXTENDED_ERROR}
pattern SECPKG_FLAG_IMPERSONATION = SecPkgCapabilities #{const SECPKG_FLAG_IMPERSONATION}
pattern SECPKG_FLAG_ACCEPT_WIN32_NAME = SecPkgCapabilities #{const SECPKG_FLAG_ACCEPT_WIN32_NAME}
pattern SECPKG_FLAG_STREAM = SecPkgCapabilities #{const SECPKG_FLAG_STREAM}
pattern SECPKG_FLAG_NEGOTIABLE = SecPkgCapabilities #{const SECPKG_FLAG_NEGOTIABLE}
pattern SECPKG_FLAG_GSS_COMPATIBLE = SecPkgCapabilities #{const SECPKG_FLAG_GSS_COMPATIBLE}
pattern SECPKG_FLAG_LOGON = SecPkgCapabilities #{const SECPKG_FLAG_LOGON}
pattern SECPKG_FLAG_ASCII_BUFFERS = SecPkgCapabilities #{const SECPKG_FLAG_ASCII_BUFFERS}
pattern SECPKG_FLAG_FRAGMENT = SecPkgCapabilities #{const SECPKG_FLAG_FRAGMENT}
pattern SECPKG_FLAG_MUTUAL_AUTH = SecPkgCapabilities #{const SECPKG_FLAG_MUTUAL_AUTH}
pattern SECPKG_FLAG_DELEGATION = SecPkgCapabilities #{const SECPKG_FLAG_DELEGATION}
pattern SECPKG_FLAG_READONLY_WITH_CHECKSUM = SecPkgCapabilities #{const SECPKG_FLAG_READONLY_WITH_CHECKSUM}
pattern SECPKG_FLAG_RESTRICTED_TOKENS = SecPkgCapabilities 0x00080000
pattern SECPKG_FLAG_NEGO_EXTENDER = SecPkgCapabilities 0x00100000
pattern SECPKG_FLAG_NEGOTIABLE2 = SecPkgCapabilities 0x00200000
pattern SECPKG_FLAG_APPCONTAINER_PASSTHROUGH = SecPkgCapabilities 0x00400000
pattern SECPKG_FLAG_APPCONTAINER_CHECKS = SecPkgCapabilities 0x00800000

secPkgCapabilitiesNames :: [ (SecPkgCapabilities, String) ]
secPkgCapabilitiesNames =
  [ (SECPKG_FLAG_INTEGRITY, "SECPKG_FLAG_INTEGRITY")
  , (SECPKG_FLAG_PRIVACY, "SECPKG_FLAG_PRIVACY")
  , (SECPKG_FLAG_TOKEN_ONLY, "SECPKG_FLAG_TOKEN_ONLY")
  , (SECPKG_FLAG_DATAGRAM, "SECPKG_FLAG_DATAGRAM")
  , (SECPKG_FLAG_CONNECTION, "SECPKG_FLAG_CONNECTION")
  , (SECPKG_FLAG_MULTI_REQUIRED, "SECPKG_FLAG_MULTI_REQUIRED")
  , (SECPKG_FLAG_CLIENT_ONLY, "SECPKG_FLAG_CLIENT_ONLY")
  , (SECPKG_FLAG_EXTENDED_ERROR, "SECPKG_FLAG_EXTENDED_ERROR")
  , (SECPKG_FLAG_IMPERSONATION, "SECPKG_FLAG_IMPERSONATION")
  , (SECPKG_FLAG_ACCEPT_WIN32_NAME, "SECPKG_FLAG_ACCEPT_WIN32_NAME")
  , (SECPKG_FLAG_STREAM, "SECPKG_FLAG_STREAM")
  , (SECPKG_FLAG_NEGOTIABLE, "SECPKG_FLAG_NEGOTIABLE")
  , (SECPKG_FLAG_GSS_COMPATIBLE, "SECPKG_FLAG_GSS_COMPATIBLE")
  , (SECPKG_FLAG_LOGON, "SECPKG_FLAG_LOGON")
  , (SECPKG_FLAG_ASCII_BUFFERS, "SECPKG_FLAG_ASCII_BUFFERS")
  , (SECPKG_FLAG_FRAGMENT, "SECPKG_FLAG_FRAGMENT")
  , (SECPKG_FLAG_MUTUAL_AUTH, "SECPKG_FLAG_MUTUAL_AUTH")
  , (SECPKG_FLAG_DELEGATION, "SECPKG_FLAG_DELEGATION")
  , (SECPKG_FLAG_READONLY_WITH_CHECKSUM, "SECPKG_FLAG_READONLY_WITH_CHECKSUM")
  , (SECPKG_FLAG_RESTRICTED_TOKENS, "SECPKG_FLAG_RESTRICTED_TOKENS")
  , (SECPKG_FLAG_NEGO_EXTENDER, "SECPKG_FLAG_NEGO_EXTENDER")
  , (SECPKG_FLAG_NEGOTIABLE2, "SECPKG_FLAG_NEGOTIABLE2")
  , (SECPKG_FLAG_APPCONTAINER_PASSTHROUGH, "SECPKG_FLAG_APPCONTAINER_PASSTHROUGH")
  , (SECPKG_FLAG_APPCONTAINER_CHECKS, "SECPKG_FLAG_APPCONTAINER_CHECKS")
  ]

instance Show SecPkgCapabilities where
  show x = printf "SecPkgCapabilities{ %s }" (parseBitFlags secPkgCapabilitiesNames unSecPkgCapabilities x)

data SecPkgInfoRaw = SecPkgInfoRaw
  { fCapabilities :: CULong
  , wVersion :: CUShort
  , wRPCID :: CUShort
  , cbMaxToken :: CULong
  , szName :: LPWSTR
  , szComment :: LPWSTR
  }

type PSecPkgInfoRaw = Ptr SecPkgInfoRaw

instance Storable SecPkgInfoRaw where
  sizeOf _ = #{size SecPkgInfo}
  alignment _ = alignment (undefined :: CInt)
  poke p x = do
    #{poke SecPkgInfo, fCapabilities} p $ fCapabilities x
    #{poke SecPkgInfo, wVersion} p $ wVersion x
    #{poke SecPkgInfo, wRPCID} p $ wRPCID x
    #{poke SecPkgInfo, cbMaxToken} p $ cbMaxToken x
    #{poke SecPkgInfo, Name} p $ szName x
    #{poke SecPkgInfo, Comment} p $ szComment x
  peek p = SecPkgInfoRaw
    <$> #{peek SecPkgInfo, fCapabilities} p
    <*> #{peek SecPkgInfo, wVersion} p
    <*> #{peek SecPkgInfo, wRPCID} p
    <*> #{peek SecPkgInfo, cbMaxToken} p
    <*> #{peek SecPkgInfo, Name} p
    <*> #{peek SecPkgInfo, Comment} p

-- SECURITY_STATUS SEC_Entry QuerySecurityPackageInfo(
--   _In_  SEC_CHAR    *pszPackageName,
--   _Out_ PSecPkgInfo *ppPackageInfo
-- );
foreign import WINDOWS_CCONV "windows.h QuerySecurityPackageInfoW"
  c_QuerySecurityPackageInfo
    :: LPWSTR -- pszPackageName
    -> Ptr PSecPkgInfoRaw -- ppPackageInfo
    -> IO SecurityStatus

-- SECURITY_STATUS SEC_Entry CompleteAuthToken(
--   _In_ PCtxtHandle    phContext,
--   _In_ PSecBufferDesc pToken
-- );
foreign import WINDOWS_CCONV "windows.h CompleteAuthToken"
  c_CompleteAuthToken
    :: PCtxtHandle -- phContext
    -> PRawSecBufferDesc -- pToken
    -> IO SecurityStatus

-- SECURITY_STATUS SEC_Entry EnumerateSecurityPackages(
--   _In_ PULONG      pcPackages,
--   _In_ PSecPkgInfo *ppPackageInfo
-- );
foreign import WINDOWS_CCONV "windows.h EnumerateSecurityPackagesW"
  c_EnumerateSecurityPackages
    :: Ptr CULong -- pcPackages
    -> Ptr PSecPkgInfoRaw -- ppPackageInfo
    -> IO SecurityStatus

data HMAPPER

newtype SChannelProt = SChannelProt { unSChannelProt :: DWORD }
  deriving (Eq, Bits, Storable)

pattern SP_PROT_PCT1_SERVER = SChannelProt 0x00000001
pattern SP_PROT_PCT1_CLIENT = SChannelProt 0x00000002
pattern SP_PROT_SSL2_SERVER = SChannelProt 0x00000004
pattern SP_PROT_SSL2_CLIENT = SChannelProt 0x00000008
pattern SP_PROT_SSL3_SERVER = SChannelProt 0x00000010
pattern SP_PROT_SSL3_CLIENT = SChannelProt 0x00000020
pattern SP_PROT_TLS1_SERVER = SChannelProt 0x00000040
pattern SP_PROT_TLS1_CLIENT = SChannelProt 0x00000080
pattern SP_PROT_TLS1_1_SERVER = SChannelProt 0x00000100
pattern SP_PROT_TLS1_1_CLIENT = SChannelProt 0x00000200
pattern SP_PROT_TLS1_2_SERVER = SChannelProt 0x00000400
pattern SP_PROT_TLS1_2_CLIENT = SChannelProt 0x00000800

sChannelProtNames :: [(SChannelProt, String)]
sChannelProtNames =
  [ (SP_PROT_PCT1_SERVER, "SP_PROT_PCT1_SERVER")
  , (SP_PROT_PCT1_CLIENT, "SP_PROT_PCT1_CLIENT")
  , (SP_PROT_SSL2_SERVER, "SP_PROT_SSL2_SERVER")
  , (SP_PROT_SSL2_CLIENT, "SP_PROT_SSL2_CLIENT")
  , (SP_PROT_SSL3_SERVER, "SP_PROT_SSL3_SERVER")
  , (SP_PROT_SSL3_CLIENT, "SP_PROT_SSL3_CLIENT")
  , (SP_PROT_TLS1_SERVER, "SP_PROT_TLS1_SERVER")
  , (SP_PROT_TLS1_CLIENT, "SP_PROT_TLS1_CLIENT")
  , (SP_PROT_TLS1_1_SERVER, "SP_PROT_TLS1_1_SERVER")
  , (SP_PROT_TLS1_1_CLIENT, "SP_PROT_TLS1_1_CLIENT")
  , (SP_PROT_TLS1_2_SERVER, "SP_PROT_TLS1_2_SERVER")
  , (SP_PROT_TLS1_2_CLIENT, "SP_PROT_TLS1_2_CLIENT")
  ]

instance Show SChannelProt where
  show x = printf "SChannelProt{ %s }" (parseBitFlags sChannelProtNames unSChannelProt x)

newtype SChannelCredFlags = SChannelCredFlags { unSChannelCredFlags :: DWORD }
  deriving (Eq, Bits, Storable)

pattern SCH_CRED_NO_SYSTEM_MAPPER = SChannelCredFlags 0x00000002
pattern SCH_CRED_NO_SERVERNAME_CHECK = SChannelCredFlags 0x00000004
pattern SCH_CRED_MANUAL_CRED_VALIDATION = SChannelCredFlags 0x00000008
pattern SCH_CRED_NO_DEFAULT_CREDS = SChannelCredFlags 0x00000010
pattern SCH_CRED_AUTO_CRED_VALIDATION = SChannelCredFlags 0x00000020
pattern SCH_CRED_USE_DEFAULT_CREDS = SChannelCredFlags 0x00000040
pattern SCH_CRED_DISABLE_RECONNECTS = SChannelCredFlags 0x00000080
pattern SCH_CRED_REVOCATION_CHECK_END_CERT = SChannelCredFlags 0x00000100
pattern SCH_CRED_REVOCATION_CHECK_CHAIN = SChannelCredFlags 0x00000200
pattern SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = SChannelCredFlags 0x00000400
pattern SCH_CRED_IGNORE_NO_REVOCATION_CHECK = SChannelCredFlags 0x00000800
pattern SCH_CRED_IGNORE_REVOCATION_OFFLINE = SChannelCredFlags 0x00001000
pattern SCH_CRED_RESTRICTED_ROOTS = SChannelCredFlags 0x00002000
pattern SCH_CRED_REVOCATION_CHECK_CACHE_ONLY = SChannelCredFlags 0x00004000
pattern SCH_CRED_CACHE_ONLY_URL_RETRIEVAL = SChannelCredFlags 0x00008000
pattern SCH_CRED_MEMORY_STORE_CERT = SChannelCredFlags 0x00010000
pattern SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE = SChannelCredFlags 0x00020000
pattern SCH_SEND_ROOT_CERT = SChannelCredFlags 0x00040000
pattern SCH_CRED_SNI_CREDENTIAL = SChannelCredFlags 0x00080000
pattern SCH_CRED_SNI_ENABLE_OCSP = SChannelCredFlags 0x00100000
pattern SCH_SEND_AUX_RECORD = SChannelCredFlags 0x00200000
pattern SCH_USE_STRONG_CRYPTO = SChannelCredFlags 0x00400000

sChannelCredFlagsNames :: [(SChannelCredFlags, String)]
sChannelCredFlagsNames =
  [ (SCH_CRED_NO_SYSTEM_MAPPER, "SCH_CRED_NO_SYSTEM_MAPPER")
  , (SCH_CRED_NO_SERVERNAME_CHECK, "SCH_CRED_NO_SERVERNAME_CHECK")
  , (SCH_CRED_MANUAL_CRED_VALIDATION, "SCH_CRED_MANUAL_CRED_VALIDATION")
  , (SCH_CRED_NO_DEFAULT_CREDS, "SCH_CRED_NO_DEFAULT_CREDS")
  , (SCH_CRED_AUTO_CRED_VALIDATION, "SCH_CRED_AUTO_CRED_VALIDATION")
  , (SCH_CRED_USE_DEFAULT_CREDS, "SCH_CRED_USE_DEFAULT_CREDS")
  , (SCH_CRED_DISABLE_RECONNECTS, "SCH_CRED_DISABLE_RECONNECTS")
  , (SCH_CRED_REVOCATION_CHECK_END_CERT, "SCH_CRED_REVOCATION_CHECK_END_CERT")
  , (SCH_CRED_REVOCATION_CHECK_CHAIN, "SCH_CRED_REVOCATION_CHECK_CHAIN")
  , (SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, "SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT")
  , (SCH_CRED_IGNORE_NO_REVOCATION_CHECK, "SCH_CRED_IGNORE_NO_REVOCATION_CHECK")
  , (SCH_CRED_IGNORE_REVOCATION_OFFLINE, "SCH_CRED_IGNORE_REVOCATION_OFFLINE")
  , (SCH_CRED_RESTRICTED_ROOTS, "SCH_CRED_RESTRICTED_ROOTS")
  , (SCH_CRED_REVOCATION_CHECK_CACHE_ONLY, "SCH_CRED_REVOCATION_CHECK_CACHE_ONLY")
  , (SCH_CRED_CACHE_ONLY_URL_RETRIEVAL, "SCH_CRED_CACHE_ONLY_URL_RETRIEVAL")
  , (SCH_CRED_MEMORY_STORE_CERT, "SCH_CRED_MEMORY_STORE_CERT")
  , (SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE, "SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE")
  , (SCH_SEND_ROOT_CERT, "SCH_SEND_ROOT_CERT")
  , (SCH_CRED_SNI_CREDENTIAL, "SCH_CRED_SNI_CREDENTIAL")
  , (SCH_CRED_SNI_ENABLE_OCSP, "SCH_CRED_SNI_ENABLE_OCSP")
  , (SCH_SEND_AUX_RECORD, "SCH_SEND_AUX_RECORD")
  , (SCH_USE_STRONG_CRYPTO, "SCH_USE_STRONG_CRYPTO")
  ]

instance Show SChannelCredFlags where
  show x = printf "SChannelCredFlags{ %s }" (parseBitFlags sChannelCredFlagsNames unSChannelCredFlags x)

newtype SChannelCredFormat = SChannelCredFormat { unSChannelCredFormat :: DWORD }
  deriving (Eq, Storable)

pattern SCH_CRED_FORMAT_CERT_HASH = SChannelCredFormat #{const SCH_CRED_FORMAT_CERT_HASH}
pattern SCH_CRED_FORMAT_CERT_HASH_STORE = SChannelCredFormat 0x00000002

sChannelCredFormatNames :: [(SChannelCredFormat, String)]
sChannelCredFormatNames =
  [ (SCH_CRED_FORMAT_CERT_HASH, "SCH_CRED_FORMAT_CERT_HASH")
  , (SCH_CRED_FORMAT_CERT_HASH_STORE, "SCH_CRED_FORMAT_CERT_HASH_STORE")
  ]

instance Show SChannelCredFormat where
  show x = printf "SChannelCredFormat{ %s }" (pickName sChannelCredFormatNames unSChannelCredFormat x)

newtype SChannelCredVersion = SChannelCredVersion { unSChannelCredVersion :: DWORD }
  deriving (Eq, Storable, Show)

pattern SCHANNEL_CRED_VERSION = SChannelCredVersion #{const SCHANNEL_CRED_VERSION}

data SCHANNEL_CRED = SCHANNEL_CRED
  { schannelDwVersion               :: SChannelCredVersion
  , schannelCCreds                  :: DWORD
  , schannelPaCred                  :: Ptr PCERT_CONTEXT
  , schannelHRootStore              :: HCERTSTORE
  , schannelCMappers                :: DWORD
  , schannelAphMappers              :: Ptr (Ptr HMAPPER)
  , schannelCSupportedAlgs          :: DWORD
  , schannelPalgSupportedAlgs       :: Ptr ALG_ID
  , schannelGrbitEnabledProtocols   :: SChannelProt
  , schannelDwMinimumCipherStrength :: DWORD
  , schannelDwMaximumCipherStrength :: DWORD
  , schannelDwSessionLifespan       :: DWORD
  , schannelDwFlags                 :: SChannelCredFlags
  , schannelDwCredFormat            :: SChannelCredFormat
  } deriving (Show)

instance Storable SCHANNEL_CRED where
  sizeOf _ = #{size SCHANNEL_CRED}
  alignment _ = alignment (undefined :: CInt)
  poke p x = do
    #{poke SCHANNEL_CRED, dwVersion} p $ schannelDwVersion x
    #{poke SCHANNEL_CRED, cCreds} p $ schannelCCreds x
    #{poke SCHANNEL_CRED, paCred} p $ schannelPaCred x
    #{poke SCHANNEL_CRED, hRootStore} p $ schannelHRootStore x
    #{poke SCHANNEL_CRED, cMappers} p $ schannelCMappers x
    #{poke SCHANNEL_CRED, aphMappers} p $ schannelAphMappers x
    #{poke SCHANNEL_CRED, cSupportedAlgs} p $ schannelCSupportedAlgs x
    #{poke SCHANNEL_CRED, palgSupportedAlgs} p $ schannelPalgSupportedAlgs x
    #{poke SCHANNEL_CRED, grbitEnabledProtocols} p $ schannelGrbitEnabledProtocols x
    #{poke SCHANNEL_CRED, dwMinimumCipherStrength} p $ schannelDwMinimumCipherStrength x
    #{poke SCHANNEL_CRED, dwMaximumCipherStrength} p $ schannelDwMaximumCipherStrength x
    #{poke SCHANNEL_CRED, dwSessionLifespan} p $ schannelDwSessionLifespan x
    #{poke SCHANNEL_CRED, dwFlags} p $ schannelDwFlags x
    #{poke SCHANNEL_CRED, dwCredFormat} p $ schannelDwCredFormat x
  peek p = SCHANNEL_CRED
    <$> #{peek SCHANNEL_CRED, dwVersion} p
    <*> #{peek SCHANNEL_CRED, cCreds} p
    <*> #{peek SCHANNEL_CRED, paCred} p
    <*> #{peek SCHANNEL_CRED, hRootStore} p
    <*> #{peek SCHANNEL_CRED, cMappers} p
    <*> #{peek SCHANNEL_CRED, aphMappers} p
    <*> #{peek SCHANNEL_CRED, cSupportedAlgs} p
    <*> #{peek SCHANNEL_CRED, palgSupportedAlgs} p
    <*> #{peek SCHANNEL_CRED, grbitEnabledProtocols} p
    <*> #{peek SCHANNEL_CRED, dwMinimumCipherStrength} p
    <*> #{peek SCHANNEL_CRED, dwMaximumCipherStrength} p
    <*> #{peek SCHANNEL_CRED, dwSessionLifespan} p
    <*> #{peek SCHANNEL_CRED, dwFlags} p
    <*> #{peek SCHANNEL_CRED, dwCredFormat} p
