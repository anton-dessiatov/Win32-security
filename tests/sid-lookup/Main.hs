module Main (main) where

import System.Environment
import System.Win32.Security.Sid
import qualified Data.Text as T

main :: IO ()
main = do
  args <- getArgs
  case args of
    domainName:accountName:[] ->
      lookupAccountName (Just $ T.pack domainName) (T.pack accountName) >>= printMaybeAcct
    accountName:[] ->
      lookupAccountName Nothing (T.pack accountName) >>= printMaybeAcct
    _ ->
      putStrLn "Either 2 args (domain name and account name) or 1 (account name) are expected"

printMaybeAcct :: Maybe LookedUpAccount -> IO ()
printMaybeAcct maybel = case maybel of
  Just l -> do
    print (lookedUpAccountName l)
    print (lookedUpReferencedDomainName l)
    print (lookedUpUse l)
    s <- convertSidToStringSid (lookedUpSid l)
    print s
  Nothing ->
    putStrLn "Nothing found"
