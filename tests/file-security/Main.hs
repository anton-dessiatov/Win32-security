module Main (main) where

import Control.Monad (join)
import Data.Bits
import Data.Maybe
import System.Environment
import System.Win32.Security.AccessControl
import System.Win32.Security.SecurityInfo
import System.Win32.Security.Sid
import qualified Data.Text as T
import qualified Data.Traversable as T

main :: IO ()
main = do
  args <- getArgs
  case args of
    act:fileName:[] -> performAction act fileName
    _ -> putStrLn "2 arguments are expected: action (either \"read\" or \"modify\") and a file name"

performAction :: String -> FilePath -> IO ()
performAction "read" fileName = do
  sinfo <- getNamedSecurityInfo (T.pack fileName) securityObjectFile
    (securityInformationOwner .|. securityInformationGroup .|. securityInformationDacl)
  printSecurityInfo sinfo
performAction "modify" fileName = do
  let textFileName = T.pack fileName
  sinfo <- getNamedSecurityInfo textFileName securityObjectFile securityInformationDacl
  let oldDacl = fromJust $ securityInfoDacl sinfo
      newDacl = aclFromList . tail $ aclToList oldDacl
  putStrLn "Old DACL was:"
  printAcl oldDacl
  putStrLn "New DACL will be:"
  printAcl newDacl
  setNamedSecurityInfo textFileName securityObjectFile Nothing Nothing (Just newDacl) Nothing

printSecurityInfo :: GetSecurityInfoResult -> IO ()
printSecurityInfo gsir = do
  putStrLn "Owner:"
  maybeOwnerAcct <- T.forM (securityInfoOwner gsir) $ lookupAccountSid Nothing
  printMaybeAcct $ join maybeOwnerAcct
  putStrLn "Group:"
  maybeGroupAcct <- T.forM (securityInfoGroup gsir) $ lookupAccountSid Nothing
  printMaybeAcct $ join maybeGroupAcct
  putStrLn "DACL:"
  let dacl = securityInfoDacl gsir
  case dacl of
    Just x  -> printAcl x
    Nothing -> putStrLn "Missing"

printMaybeAcct :: Maybe LookedUpAccount -> IO ()
printMaybeAcct maybel = case maybel of
  Just l -> do
    print (lookedUpAccountName l)
    print (lookedUpReferencedDomainName l)
    print (lookedUpUse l)
    s <- convertSidToStringSid (lookedUpSid l)
    print s
  Nothing ->
    putStrLn "Unknown"

printAcl :: Acl -> IO ()
printAcl acl = do
    putStrLn $ concat [ "ACL Entries count: ", show $ aclEntriesCount acl ]
    mapM_ printAce $ aclToList acl
  where
    printAce ace = case ace of
      AceAccessAllowed ga -> do
        putStrLn "ACCESS_ALLOWED_ACE"
        printGenericAce ga
      AceAccessDenied ga -> do
        putStrLn "ACCESS_DENIED_ACE"
        printGenericAce ga
    printGenericAce ga = do
      putStrLn $ concat [ "ACE Flags: ", show $ genericAceFlags ga ]
      putStrLn $ concat [ "ACE AccessMask: ", show $ genericAceAccessMask ga ]
      sidString <- convertSidToStringSid $ genericAceSid ga
      putStrLn $ concat [ "ACE Sid: ", show sidString ]
      putStrLn "Sid lookup: "
      sidLookup <- lookupAccountSid Nothing $ genericAceSid ga
      printMaybeAcct sidLookup

