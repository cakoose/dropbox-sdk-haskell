module Main where

import qualified Dropbox as DB
import System.Exit (exitFailure)
import System.Environment (getArgs)
import System.IO (hGetLine, hPutStrLn, stderr, stdout, stdin)
import qualified Data.ByteString.Char8 as C8

hostsDev = DB.Hosts "meta.dbdev.corp.dropbox.com" "api.dbdev.corp.dropbox.com" "api-content.dbdev.corp.dropbox.com"

main :: IO ()
main = do
    args <- getArgs
    case args of
        [appKey, appSecret] -> mainProd appKey appSecret
        _ -> do
            putStrLn "Usage: COMMAND app-key app-secret"
            exitFailure

mainProd = main_ DB.hostsDefault

mainDev = main_ hostsDev

mkConfig hosts appKey appSecret = do
    base <- DB.mkConfig DB.localeEn appKey appSecret DB.AccessTypeDropbox
    return $ base { DB.configHosts = hosts }

auth mgr config = do
    -- OAuth
    (requestToken, authUrl) <- DB.authStart mgr config Nothing
        `dieOnFailure` "Couldn't get request token"
    hPutStrLn stdout $ "Request Token: " ++ show requestToken
    hPutStrLn stdout $ "Auth URL: " ++ authUrl
    hGetLine stdin
    (accessToken, userId) <- DB.authFinish mgr config requestToken
        `dieOnFailure` "Couldn't get access token"
    hPutStrLn stdout $ "Access Token: " ++ show accessToken
    return accessToken

accountInfo mgr session = do
    accountInfo <- DB.getAccountInfo mgr session
        `dieOnFailure` "Couldn't get account info"
    hPutStrLn stdout $ "---- Account Info ----"
    hPutStrLn stdout $ show accountInfo

rootMetadata mgr session = do
    (DB.Meta meta extra, mContents) <- DB.getMetadataWithChildren mgr session "/" Nothing
        `dieOnFailure` "Couldn't get root folder listing"
    (hash, children) <- case mContents of
        Just (DB.FolderContents hash children) -> return (hash, children)
        _ -> die "Root is not a folder?  What the poop?"
    hPutStrLn stdout $ "---- Files ----"
    mapM_ ((hPutStrLn stdout).show) children
    secondTime <- DB.getMetadataWithChildrenIfChanged mgr session "/" Nothing hash
        `dieOnFailure` "Couldn't get root folder listing again"
    hPutStrLn stdout (show secondTime) -- Will almost always print "Nothing" (i.e. "nothing has changed")

addFile mgr session = do
    DB.addFile mgr session "/Facts.txt" (DB.bsRequestBody $ C8.pack "Rian hates types.\n")
        `dieOnFailure` "Couldn't add Facts.txt"

getFileContents mgr session = do
    contents <- DB.getFileContents mgr session "/Facts.txt" Nothing
        `dieOnFailure` "Couldn't read Facts.txt"
    C8.putStrLn contents

main_ :: DB.Hosts -> String -> String -> IO ()
main_ hosts appKey appSecret = do
    config <- mkConfig hosts appKey appSecret
    DB.withManager $ \mgr -> do
        accessToken <- auth mgr config
        let session = DB.Session config accessToken
        accountInfo mgr session
        rootMetadata mgr session
        addFile mgr session
        getFileContents mgr session
        return ()

dieOnFailure :: IO (Either String v) -> String -> IO v
dieOnFailure action errorPrefix = do
    ev <- action
    case ev of
        Left err -> die (errorPrefix ++ ": " ++ err)
        Right result -> return result

die message = do
    hPutStrLn stderr message
    exitFailure
