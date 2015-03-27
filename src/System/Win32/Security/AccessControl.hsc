{-# LANGUAGE CPP, GeneralizedNewtypeDeriving, OverloadedStrings, RankNTypes, ScopedTypeVariables #-}
module System.Win32.Security.AccessControl
  ( Acl (..)
  , aclEntriesCount
  , AceFlags (..)
  , aceFlagContainerInherit
  , aceFlagFailedAccess
  , aceFlagInheritOnly
  , aceFlagInherited
  , aceFlagNoPropagateInherit
  , aceFlagObjectInherit
  , aceFlagSuccessfulAccess
  , AccessMask (..)
  , Ace (..)
  , GenericAce (..)
  , aclToList
  , aclFromList
  ) where

import Control.Applicative ((<$>))
import Control.Monad (foldM_)
import Data.Bits
import Foreign
-- I have to use GHC internal ForeignPtr module because that one exports mallocForeignPtrAlignedBytes
-- function, and I have to make ACL buffers DWORD-aligned.
import GHC.ForeignPtr
import System.Win32.Security
import System.Win32.Security.Sid
import System.Win32.Types
import System.IO.Unsafe
import qualified System.Win32.Error.Foreign as E

#include <windows.h>

-- | Access control list.
newtype Acl = Acl { withAclPtr :: forall a. (PACL -> IO a) -> IO a }

aclEntriesCount :: Acl -> Int
aclEntriesCount acl = fromIntegral . unsafePerformIO $ withAclPtr acl peekAceCount
  where peekAceCount :: PACL -> IO WORD
        peekAceCount = #{peek ACL, AceCount}

newtype AceFlags = AceFlags { aceFlagsGetValue :: BYTE }
  deriving (Eq, Bits, Show)

#{enum AceFlags, AceFlags
 , aceFlagContainerInherit   = CONTAINER_INHERIT_ACE
 , aceFlagFailedAccess       = FAILED_ACCESS_ACE_FLAG
 , aceFlagInheritOnly        = INHERIT_ONLY_ACE
 , aceFlagInherited          = INHERITED_ACE
 , aceFlagNoPropagateInherit = NO_PROPAGATE_INHERIT_ACE
 , aceFlagObjectInherit      = OBJECT_INHERIT_ACE
 , aceFlagSuccessfulAccess   = SUCCESSFUL_ACCESS_ACE_FLAG
 }

newtype AccessMask = AccessMask { accessMaskGetValue :: DWORD }
  deriving (Eq, Bits, Show)

-- | Not all ACE types are currently supported. Exotic ones like ACCESS_ALLOWED_CALLBACK_OBJECT_ACE are
-- not implemented. Feel free to contact me if you REALLY need it.
data Ace
  = AceAccessAllowed GenericAce
  | AceAccessDenied GenericAce
  | AceUnknown

data GenericAce = GenericAce
  { genericAceFlags      :: AceFlags
  , genericAceAccessMask :: AccessMask
  , genericAceSid        :: Sid
  }

aclToList :: Acl -> [Ace]
aclToList acl = reverse . unsafePerformIO $ go [] (aclEntriesCount acl) #{size ACL}
  where
    -- This one accumulates Ace entries in reverse order (reverse is to avoid unnecessary list
    -- traversals with (++))
    go :: [Ace] -> Int -> Int -> IO [Ace]
    go result 0 _ = return result
    go currentList remainingAces currentOffset = withAclPtr acl $ \pAcl -> do
      let currentPtr = pAcl `plusPtr` currentOffset
      (headerType :: BYTE) <- #{peek ACE_HEADER, AceType} currentPtr
      (headerFlags :: BYTE) <- #{peek ACE_HEADER, AceFlags} currentPtr
      (headerSize :: WORD) <- #{peek ACE_HEADER, AceSize} currentPtr
      newAce <- case headerType of
        #{const ACCESS_ALLOWED_ACE_TYPE} -> AceAccessAllowed <$>
          parseGenericAce (AceFlags headerFlags) (fromIntegral headerSize) currentOffset
        #{const ACCESS_DENIED_ACE_TYPE} -> AceAccessDenied <$>
          parseGenericAce (AceFlags headerFlags) (fromIntegral headerSize) currentOffset
        _ -> return AceUnknown
      go (newAce:currentList) (remainingAces - 1) (currentOffset + fromIntegral headerSize)

    parseGenericAce :: AceFlags -> Int -> Int -> IO GenericAce
    parseGenericAce flags size currentOffset = withAclPtr acl $ \pAcl -> do
      let currentPtr = pAcl `plusPtr` currentOffset
      (mask :: DWORD) <- #{peek ACCESS_ALLOWED_ACE, Mask} currentPtr
      -- All this black magic is to avoid copying the SID and instead refer to it using a
      -- withAclPtr function (to prevent it from being consumed by GC)
      let sid = Sid $ \act -> withAclPtr acl $ \pAcl -> act (pAcl `plusPtr` currentOffset `plusPtr` #{offset ACCESS_ALLOWED_ACE, SidStart})
      return $ GenericAce flags (AccessMask mask) sid

-- | Calculates amount of memory required by a given ACE
aceSize :: Ace -> Int
aceSize ace = case ace of
  AceAccessAllowed ga -> #{size ACCESS_ALLOWED_ACE} + getLengthSid (genericAceSid ga) - #{size DWORD}
  AceAccessDenied ga  -> #{size ACCESS_DENIED_ACE} + getLengthSid (genericAceSid ga) - #{size DWORD}

-- | Serializes given ACE to a given buffer. Buffer should have at least 'aceSize' bytes.
serializeAce :: Ace -> Ptr () -> IO ()
serializeAce ace dest = do
    #{poke ACE_HEADER, AceSize} dest (fromIntegral $ aceSize ace :: WORD)
    case ace of
      AceAccessAllowed ga -> do
        #{poke ACE_HEADER, AceType} dest (#{const ACCESS_ALLOWED_ACE_TYPE} :: BYTE)
        serializeGenericAce ga
      AceAccessDenied ga -> do
        #{poke ACE_HEADER, AceType} dest (#{const ACCESS_DENIED_ACE_TYPE} :: BYTE)
        serializeGenericAce ga
      AceUnknown -> error "Adding AceUnknown to ACL is not supported"
  where
    serializeGenericAce :: GenericAce -> IO ()
    serializeGenericAce ga = do
      #{poke ACE_HEADER, AceFlags} dest (aceFlagsGetValue $ genericAceFlags ga)
      #{poke ACCESS_ALLOWED_ACE, Mask} dest (accessMaskGetValue $ genericAceAccessMask ga)
      let sid = genericAceSid ga
          sidLength = getLengthSid sid
          aceSidPtr = dest `plusPtr` #{offset ACCESS_ALLOWED_ACE, SidStart}
      withSidPtr sid $ \pSid ->
        copyBytes aceSidPtr pSid sidLength

-- | Creates an Acl from a list of access control entries. ACL revision is assumed to be ACL_REVISION because
-- ACL_REVISION_DS is not supported yet.
aclFromList :: [Ace] -> Acl
aclFromList aces =
  let acesAndSizes = map (\ace -> (ace, aceSize ace)) aces
      aclSize = #{size ACL} + (sum $ map snd acesAndSizes)
  in unsafePerformIO $ do
    aclData <- mallocForeignPtrAlignedBytes aclSize #{size DWORD}
    withForeignPtr aclData $ \pAcl -> do
      E.failIfFalse_ "InitializeAcl" $
        c_InitializeAcl pAcl (fromIntegral aclSize) #{const ACL_REVISION}
      #{poke ACL, AceCount} pAcl (fromIntegral $ length aces :: WORD)
      foldM_
        (\ptr (ace, size) -> serializeAce ace ptr >> return (ptr `plusPtr` size))
        (pAcl `plusPtr` #{size ACL})
        acesAndSizes
    return $ Acl $ withForeignPtr aclData

foreign import WINDOWS_CCONV unsafe "windows.h InitializeAcl"
  c_InitializeAcl
    :: PACL -- pAcl
    -> DWORD -- nAclLength
    -> DWORD -- dwAclRevision
    -> IO BOOL

-- | Creates a copy of a given Acl structure. This is mostly used internally to establish an immutable data
-- interface.
aclCopy :: Acl -> IO Acl
aclCopy acl = withAclPtr acl $ \pAcl -> do
    size <- fromIntegral <$> peekAceSize pAcl
    newAcl <- mallocForeignPtrBytes size
    withForeignPtr newAcl $ \pNewAcl ->
      copyBytes pNewAcl pAcl size
    return $ Acl $ withForeignPtr newAcl
  where
    peekAceSize :: PACL -> IO WORD
    peekAceSize = #{peek ACL, AclSize}
