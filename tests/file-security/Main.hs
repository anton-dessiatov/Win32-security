module Main (main) where

import Control.Monad (join)
import Data.Bits
import System.Environment
import System.Win32.Security.SecurityDescriptor
import System.Win32.Security.Sid
import qualified Data.Text as T
import qualified Data.Traversable as T

main :: IO ()
main = do
  args <- getArgs
  case args of
    fileName:[] ->
      getNamedSecurityInfo (T.pack fileName) securityObjectFile (securityInformationOwner .|. securityInformationGroup)
        >>= printSecurityInfo
    _ ->
      putStrLn "1 argument with a file name is expected"

printSecurityInfo :: GetSecurityInfoResult -> IO ()
printSecurityInfo gsir = do
  putStrLn "Owner:"
  maybeOwnerAcct <- T.forM (securityInfoOwner gsir) $ lookupAccountSid Nothing
  printMaybeAcct $ join maybeOwnerAcct
  putStrLn "Group:"
  maybeGroupAcct <- T.forM (securityInfoGroup gsir) $ lookupAccountSid Nothing
  printMaybeAcct $ join maybeGroupAcct

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

