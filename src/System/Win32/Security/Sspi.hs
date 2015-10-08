{-# LANGUAGE OverloadedStrings, PatternSynonyms #-}
module System.Win32.Security.Sspi
  ( PCredHandle
  , CredentialUse (..)
  , pattern SECPKG_CRED_INBOUND
  , pattern SECPKG_CRED_OUTBOUND
  , SecWinntAuthIdentity (..)
  , CredSSPCred (..)
  , acquireCredentialsHandle
  , PCtxtHandle
  , SecurityContextStatus (..)
  , IscRetContextAttr (..)
  , pattern ISC_RET_DELEGATE
  , pattern ISC_RET_MUTUAL_AUTH
  , pattern ISC_RET_REPLAY_DETECT
  , pattern ISC_RET_SEQUENCE_DETECT
  , pattern ISC_RET_CONFIDENTIALITY
  , pattern ISC_RET_USE_SESSION_KEY
  , pattern ISC_RET_USED_COLLECTED_CREDS
  , pattern ISC_RET_USED_SUPPLIED_CREDS
  , pattern ISC_RET_ALLOCATED_MEMORY
  , pattern ISC_RET_USED_DCE_STYLE
  , pattern ISC_RET_DATAGRAM
  , pattern ISC_RET_CONNECTION
  , pattern ISC_RET_INTERMEDIATE_RETURN
  , pattern ISC_RET_CALL_LEVEL
  , pattern ISC_RET_EXTENDED_ERROR
  , pattern ISC_RET_STREAM
  , pattern ISC_RET_INTEGRITY
  , pattern ISC_RET_IDENTIFY
  , pattern ISC_RET_NULL_SESSION
  , pattern ISC_RET_FRAGMENT_ONLY
  , iscRetContextAttrNames
  , SecurityContextResult (..)
  , IscContextReq (..)
  , pattern ISC_REQ_ALLOCATE_MEMORY
  , pattern ISC_REQ_CONNECTION
  , pattern ISC_REQ_CONFIDENTIALITY
  , pattern ISC_REQ_USE_SESSION_KEY
  , pattern ISC_REQ_EXTENDED_ERROR
  , pattern ISC_REQ_MANUAL_CRED_VALIDATION
  , pattern ISC_REQ_SEQUENCE_DETECT
  , pattern ISC_REQ_STREAM
  , pattern ISC_REQ_USE_SUPPLIED_CREDS
  , pattern ISC_REQ_DELEGATE
  , pattern ISC_REQ_MUTUAL_AUTH
  , TargetDataRep (..)
  , pattern SECURITY_NATIVE_DREP
  , pattern SECURITY_NETWORK_DREP
  , SecBuffer (..)
  , SecBufferType (..)
  , pattern SECBUFFER_ALERT
  , pattern SECBUFFER_ATTRMASK
  , pattern SECBUFFER_CHANNEL_BINDINGS
  , pattern SECBUFFER_CHANGE_PASS_RESPONSE
  , pattern SECBUFFER_DATA
  , pattern SECBUFFER_EMPTY
  , pattern SECBUFFER_EXTRA
  , pattern SECBUFFER_MECHLIST
  , pattern SECBUFFER_MECHLIST_SIGNATURE
  , pattern SECBUFFER_MISSING
  , pattern SECBUFFER_PKG_PARAMS
  , pattern SECBUFFER_STREAM_HEADER
  , pattern SECBUFFER_STREAM_TRAILER
  , pattern SECBUFFER_TARGET
  , pattern SECBUFFER_TARGET_HOST
  , pattern SECBUFFER_TOKEN
  , pattern SECBUFFER_APPLICATION_PROTOCOLS
  , pattern SECBUFFER_READONLY
  , pattern SECBUFFER_READONLY_WITH_CHECKSUM
  , initializeSecurityContext
  , AscContextReq (..)
  , pattern ASC_REQ_ALLOCATE_MEMORY
  , pattern ASC_REQ_CONNECTION
  , pattern ASC_REQ_DELEGATE
  , pattern ASC_REQ_EXTENDED_ERROR
  , pattern ASC_REQ_REPLAY_DETECT
  , pattern ASC_REQ_SEQUENCE_DETECT
  , pattern ASC_REQ_STREAM
  , AscRetContextAttr (..)
  , pattern ASC_RET_DELEGATE
  , pattern ASC_RET_MUTUAL_AUTH
  , pattern ASC_RET_REPLAY_DETECT
  , pattern ASC_RET_SEQUENCE_DETECT
  , pattern ASC_RET_CONFIDENTIALITY
  , pattern ASC_RET_USE_SESSION_KEY
  , pattern ASC_RET_SESSION_TICKET
  , pattern ASC_RET_ALLOCATED_MEMORY
  , pattern ASC_RET_USED_DCE_STYLE
  , pattern ASC_RET_DATAGRAM
  , pattern ASC_RET_CONNECTION
  , pattern ASC_RET_CALL_LEVEL
  , pattern ASC_RET_THIRD_LEG_FAILED
  , pattern ASC_RET_EXTENDED_ERROR
  , pattern ASC_RET_STREAM
  , pattern ASC_RET_INTEGRITY
  , pattern ASC_RET_LICENSING
  , pattern ASC_RET_IDENTIFY
  , pattern ASC_RET_NULL_SESSION
  , pattern ASC_RET_ALLOW_NON_USER_LOGONS
  , pattern ASC_RET_ALLOW_CONTEXT_REPLAY
  , pattern ASC_RET_FRAGMENT_ONLY
  , pattern ASC_RET_NO_TOKEN
  , pattern ASC_RET_NO_ADDITIONAL_TOKEN
  , acceptSecurityContext
  , QOP
  , pattern SECQOP_WRAP_NO_ENCRYPT
  , encryptMessage
  , decryptMessage
  , SecPkgCapabilities (..)
  , pattern SECPKG_FLAG_INTEGRITY
  , pattern SECPKG_FLAG_PRIVACY
  , pattern SECPKG_FLAG_TOKEN_ONLY
  , pattern SECPKG_FLAG_DATAGRAM
  , pattern SECPKG_FLAG_CONNECTION
  , pattern SECPKG_FLAG_MULTI_REQUIRED
  , pattern SECPKG_FLAG_CLIENT_ONLY
  , pattern SECPKG_FLAG_EXTENDED_ERROR
  , pattern SECPKG_FLAG_IMPERSONATION
  , pattern SECPKG_FLAG_ACCEPT_WIN32_NAME
  , pattern SECPKG_FLAG_STREAM
  , pattern SECPKG_FLAG_NEGOTIABLE
  , pattern SECPKG_FLAG_GSS_COMPATIBLE
  , pattern SECPKG_FLAG_LOGON
  , pattern SECPKG_FLAG_ASCII_BUFFERS
  , pattern SECPKG_FLAG_FRAGMENT
  , pattern SECPKG_FLAG_MUTUAL_AUTH
  , pattern SECPKG_FLAG_DELEGATION
  , pattern SECPKG_FLAG_READONLY_WITH_CHECKSUM
  , pattern SECPKG_FLAG_RESTRICTED_TOKENS
  , pattern SECPKG_FLAG_NEGO_EXTENDER
  , pattern SECPKG_FLAG_NEGOTIABLE2
  , pattern SECPKG_FLAG_APPCONTAINER_PASSTHROUGH
  , pattern SECPKG_FLAG_APPCONTAINER_CHECKS
  , secPkgCapabilitiesNames
  , SecPkgInfo (..)
  , querySecurityPackageInfo
  , completeAuthToken
  , enumerateSecurityPackages
  ) where

import Foreign hiding (void)
import Foreign.C.Types
import Control.Exception (bracketOnError)
import Control.Monad
import Control.Monad.Trans.Resource
import Control.Monad.IO.Class
import Data.Char (chr)
import Data.Maybe
import System.Win32.Error
import System.Win32.Error.Foreign
import System.Win32.Security.Sspi.Internal
import qualified Data.Text as T
import qualified Data.Text.Foreign as T

data SecWinntAuthIdentity = SecWinntAuthIdentity
  { authIdentityUser     :: T.Text
  , authIdentityDomain   :: T.Text
  , authIdentityPassword :: T.Text
  } deriving (Eq, Show)

withSecWinntAuthIdentity :: SecWinntAuthIdentity -> (Ptr SEC_WINNT_AUTH_IDENTITY -> IO a) -> IO a
withSecWinntAuthIdentity x act =
  T.useAsPtr (authIdentityUser x) $ \szUser userLength ->
  T.useAsPtr (authIdentityDomain x) $ \szDomain domainLength ->
  T.useAsPtr (authIdentityPassword x) $ \szPassword passwordLength ->
  let x' = SEC_WINNT_AUTH_IDENTITY
             (castPtr szUser) (fromIntegral userLength)
             (castPtr szDomain) (fromIntegral domainLength)
             (castPtr szPassword) (fromIntegral passwordLength)
             SEC_WINNT_AUTH_IDENTITY_UNICODE
  in with x' act

-- There is actually more to CREDSSP_CRED structure than just embedding SEC_WINNT_AUTH_IDENTITY
-- it's just not implemented here.
newtype CredSSPCred = CredSSPCred
  { credAuthIdentity :: SecWinntAuthIdentity
  } deriving (Eq, Show)

withCredSSPCred :: CredSSPCred -> (Ptr CREDSSP_CRED -> IO a) -> IO a
withCredSSPCred x act =
  withSecWinntAuthIdentity (credAuthIdentity x) $ \pSpnegoCred ->
  let c = CREDSSP_CRED
            -- There is some dark Windows API magic in how you are supposed to pass
            -- "both" here even if actually there are only Negotiate credentials.
            -- Passing just "Password" makes AcquireCredentialsHandle to fail with SEC_E_INVALID_TOKEN
            CredsspSubmitBufferBoth
            nullPtr
            (castPtr pSpnegoCred)
  in with c act

--
-- There is an pvLogonID parameter to underlying API function, which isn't exported.
-- If needed, it could be done trivially (except for creating wrappers for LogonID itself)
--
-- pAuthData parameter expects a pointer to a CREDSSP_CRED structure, which isn't documented
-- very helpfully. It turned out from code samples all over the Internet that its field
-- pSchannelCred expects to have a pointer to a PSCHANNEL_CRED structure and its pSpnegoCred - to
-- a SEC_WINNT_AUTH_IDENTITY one.
-- Currently we provide only means of passing SEC_WINNT_AUTH_IDENTITY there.
acquireCredentialsHandle :: (MonadResource m) =>
  Maybe T.Text -> T.Text -> CredentialUse -> Maybe CredSSPCred -> m (ReleaseKey, PCredHandle)
acquireCredentialsHandle principal package credentialUse authData = allocate create freeResource
  where create =
          maybe ($ nullPtr) useAsPtr0 principal $ \pszPrincipal ->
          useAsPtr0 package $ \pszPackage ->
          maybe ($ nullPtr) withCredSSPCred authData $ \pAuthData ->
          alloca $ \pTimestamp -> do
            pCredHandle <- malloc
            failUnlessSuccess "AcquireCredentialsHandle" $ fromIntegral <$> c_AcquireCredentialsHandle
              pszPrincipal
              pszPackage
              (unCredentialUse credentialUse)
              nullPtr -- pvLogonID
              (castPtr pAuthData) -- pAuthData
              nullPtr -- pGetKeyFn
              nullPtr -- pvGetKeyArgument
              pCredHandle
              pTimestamp
            return pCredHandle
        freeResource x = do
          void $ c_FreeCredentialsHandle x
          free x

data SecurityContextStatus
  = StatusIncompleteMessage
  -- ^ SEC_E_INCOMPLETE_MESSAGE
  | StatusOk
  -- ^ SEC_E_OK
  | StatusCompleteAndContinue
  -- ^ SEC_I_COMPLETE_AND_CONTINUE
  | StatusCompleteNeeded
  -- ^ SEC_I_COMPLETE_NEEDED
  | StatusContinueNeeded
  -- ^ SEC_I_CONTINUE_NEEDED
  | StatusIncompleteCredentials
  -- ^ SEC_I_INCOMPLETE_CREDENTIALS
  deriving (Eq, Show)

securityStatusToScStatus :: SecurityStatus -> Maybe SecurityContextStatus
securityStatusToScStatus x = case x of
  SEC_E_INCOMPLETE_MESSAGE -> Just StatusIncompleteMessage
  SEC_E_OK -> Just StatusOk
  SEC_I_COMPLETE_AND_CONTINUE -> Just StatusCompleteAndContinue
  SEC_I_COMPLETE_NEEDED -> Just StatusCompleteNeeded
  SEC_I_CONTINUE_NEEDED -> Just StatusContinueNeeded
  SEC_I_INCOMPLETE_CREDENTIALS -> Just StatusIncompleteCredentials
  _ -> Nothing

data SecurityContextResult attrs = SecurityContextResult
  { securityContextStatus :: SecurityContextStatus
  , securityContextNewContext :: Maybe (ReleaseKey, PCtxtHandle)
  -- ^ When initializeSecurityContext will not be given a PCtxtHandle, it will
  -- assume that underlying native function will allocate one and then return
  -- it here.
  , securityContextOutput :: [SecBuffer]
  -- ^ This is guaranteed to contain exactly the same buffers as the output parameter
  -- of appropriate function. Buffers contents, however, may change.
  , securityContextAttributes :: attrs
  -- There is also an expiry timestamp returned from this function. I just didn't
  -- bother with it yet.
  -- , securityContextExpiry ::
  }

-- Both input and output buffers should be specified. It's the caller responsibility
-- to properly handle the buffers lifetime and contents.
initializeSecurityContext :: Maybe PCredHandle -> Maybe PCtxtHandle -> Maybe T.Text -> IscContextReq ->
  TargetDataRep -> [SecBuffer] -> [SecBuffer] -> ResourceT IO (SecurityContextResult IscRetContextAttr)
initializeSecurityContext credential context targetName contextReq targetDataRep input output =
    securityContextHelper go
  where
    expectNewContext = isNothing context
    phCredential = fromMaybe nullPtr credential
    phContext = fromMaybe nullPtr context
    go =
      maybe ($ nullPtr) useAsPtr0 targetName $ \pszTargetName ->
      withSecBufferDesc_ input $ \pInput -> do
      ((st, nc, a), outBuf) <- withSecBufferDesc output $ \pOutput ->
        alloca $ \pfContextAttr ->
        alloca $ \ptsExpiry ->
          -- This IO action always runs masked so it's safe to assume that
          -- no async exceptions would interrupt us.
          -- The idea is to conditionally allocate space for resulting context
          -- and if there were no errors, just return that space with its dealloc
          -- function.
          bracketOnError
            (if expectNewContext then Just <$> malloc else return Nothing)
            (mapM_ free)
            (\maybeNewCtxt -> do
              rawStatus <- c_InitializeSecurityContext phCredential phContext pszTargetName
                (unIscContextReq contextReq) 0 (unTargetDataRep targetDataRep) pInput 0
                (fromMaybe nullPtr maybeNewCtxt) pOutput pfContextAttr ptsExpiry
              let maybeStatus = securityStatusToScStatus rawStatus
              case maybeStatus of
                Nothing -> failWith "InitializeSecurityContext" (Other $ fromIntegral rawStatus)
                Just status -> do
                  let newCtxt = fmap (\x -> (c_DeleteSecurityContext x >> free x, x)) maybeNewCtxt
                  attrs <- peek pfContextAttr
                  return (status, newCtxt, IscRetContextAttr attrs)
            )
      return (st, nc, a, outBuf)

acceptSecurityContext :: Maybe PCredHandle -> Maybe PCtxtHandle
  -> [SecBuffer] -> AscContextReq -> TargetDataRep -> [SecBuffer]
  -> ResourceT IO (SecurityContextResult AscRetContextAttr)
acceptSecurityContext credential context input contextReq targetDataRep output =
    securityContextHelper go
  where
    expectNewContext = isNothing context
    phCredential = fromMaybe nullPtr credential
    phContext = fromMaybe nullPtr context
    go =
      withSecBufferDesc_ input $ \pInput -> do
      ((st, nc, a), outBuf) <-
        withSecBufferDesc output $ \pOutput ->
        alloca $ \pfContextAttr ->
        alloca $ \ptsExpiry ->
          -- Same trick as in initializeSecurityContext
          bracketOnError
            (if expectNewContext then Just <$> malloc else return Nothing)
            (mapM_ free)
            (\maybeNewCtxt -> do
              rawStatus <- c_AcceptSecurityContext phCredential phContext pInput
                (unAscContextReq contextReq) (unTargetDataRep targetDataRep)
                (fromMaybe nullPtr maybeNewCtxt) pOutput pfContextAttr ptsExpiry
              let maybeStatus = securityStatusToScStatus rawStatus
              case maybeStatus of
                Nothing -> failWith "AcceptSecurityContext" (Other $ fromIntegral rawStatus)
                Just status -> do
                  let newCtxt = fmap (\x -> (c_DeleteSecurityContext x >> free x, x)) maybeNewCtxt
                  attrs <- peek pfContextAttr
                  return (status, newCtxt, AscRetContextAttr attrs)
            )
      return (st, nc, a, outBuf)

-- | Given IO action will run masked so it's safe to assume that it won't be interrupted
-- by async exception.
securityContextHelper :: (MonadResource m) =>
     IO (SecurityContextStatus, Maybe (IO (), PCtxtHandle), attrs, [SecBuffer])
  -> m (SecurityContextResult attrs)
securityContextHelper go = resourceMask $ \_ -> do
  (status, maybeNewCtxt, attrs, outBufs) <- liftIO go
  newCtxt <- forM maybeNewCtxt $ \(act, ctxt) -> do
    key <- register act
    return (key, ctxt)
  return SecurityContextResult
    { securityContextStatus = status
    , securityContextNewContext = newCtxt
    , securityContextOutput = outBufs
    , securityContextAttributes = attrs
    }

encryptMessage :: PCtxtHandle -> QOP -> [SecBuffer] -> CULong -> IO [SecBuffer]
encryptMessage context qop message seqNo =
  snd <$> (withSecBufferDesc message $ \pMessage ->
    failUnlessSuccess "EncryptMessage" $ fromIntegral <$> c_EncryptMessage context
      (unQOP qop) pMessage seqNo)

decryptMessage :: PCtxtHandle -> [SecBuffer] -> CULong -> IO (QOP, [SecBuffer])
decryptMessage context message seqNo =
  withSecBufferDesc message $ \pMessage ->
  alloca $ \pfQOP -> do
    failUnlessSuccess "DecryptMessage" $ fromIntegral <$> c_DecryptMessage context
      pMessage seqNo pfQOP
    QOP <$> peek pfQOP

withSecBufferDesc :: [SecBuffer] -> (PRawSecBufferDesc -> IO a) -> IO (a, [SecBuffer])
withSecBufferDesc buffers act =
  let buffersLength = length buffers
  in  if buffersLength == 0
        then (,) <$> act nullPtr <*> pure []
        else
          withArray buffers $ \pBuffers ->
          with (RawSecBufferDesc SECBUFFER_VERSION (fromIntegral $ length buffers) pBuffers) $ \pDesc ->
            (,) <$> act pDesc <*> peekArray buffersLength pBuffers

withSecBufferDesc_ :: [SecBuffer] -> (PRawSecBufferDesc -> IO a) -> IO a
withSecBufferDesc_ buffers act = fst <$> withSecBufferDesc buffers act

data SecPkgInfo = SecPkgInfo
  { secPkgCapabilities :: SecPkgCapabilities
  , secPkgVersion      :: CUShort
  , secPkgRPCID        :: CUShort
  , secPkgMaxToken     :: CULong
  , secPkgName         :: T.Text
  , secPkgComment      :: T.Text
  } deriving (Show)

secPkgInfoFromRaw :: SecPkgInfoRaw -> IO SecPkgInfo
secPkgInfoFromRaw rawInfo = do
  name <- fromPtr0 $ szName rawInfo
  comment <- fromPtr0 $ szComment rawInfo
  return SecPkgInfo
    { secPkgCapabilities = SecPkgCapabilities $ fCapabilities rawInfo
    , secPkgVersion = wVersion rawInfo
    , secPkgRPCID = wRPCID rawInfo
    , secPkgMaxToken = cbMaxToken rawInfo
    , secPkgName = name
    , secPkgComment = comment
    }

querySecurityPackageInfo :: T.Text -> IO (Maybe SecPkgInfo)
querySecurityPackageInfo packageName =
  useAsPtr0 packageName $ \pszPackageName ->
  alloca $ \ppPackageInfo -> do
    failUnlessSuccess "QuerySecurityPackageInfo" $ fromIntegral <$> c_QuerySecurityPackageInfo
      pszPackageName ppPackageInfo
    pPackageInfo <- peek ppPackageInfo
    if pPackageInfo == nullPtr
      then return Nothing
      else Just <$> (peek pPackageInfo >>= secPkgInfoFromRaw)

completeAuthToken :: PCtxtHandle -> [SecBuffer] -> IO [SecBuffer]
completeAuthToken context output = snd <$> (withSecBufferDesc output $ \pToken ->
  failUnlessSuccess "CompleteAuthToken" $ fromIntegral <$> c_CompleteAuthToken context pToken)

enumerateSecurityPackages :: IO [SecPkgInfo]
enumerateSecurityPackages =
  alloca $ \pcPackages ->
  alloca $ \ppPackageInfo -> do
    failUnlessSuccess "EnumerateSecurityPackages" $ fromIntegral <$> c_EnumerateSecurityPackages
      pcPackages ppPackageInfo
    cnt <- fromIntegral <$> peek pcPackages
    arr <- peek ppPackageInfo
    peekArray cnt arr >>= mapM secPkgInfoFromRaw

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
