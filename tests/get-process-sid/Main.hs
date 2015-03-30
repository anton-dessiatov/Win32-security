module Main (main) where

import System.Win32.Security.Sid

main :: IO ()
main =
  getCurrentProcess >>= getProcessUserSid >>= lookupAccountSid Nothing >>= printMaybeAcct

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
