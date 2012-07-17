module Main where

import qualified Dropbox as DB
import System.Exit (exitFailure)
import System.Environment (getArgs)
import System.IO (hGetLine, hPutStrLn, stderr, stdout, stdin)
import qualified Data.ByteString.Char8 as C8

import Control.Monad.IO.Class (liftIO)

hostsDev = DB.Hosts "meta.dbdev.corp.dropbox.com" "api.dbdev.corp.dropbox.com" "api-content.dbdev.corp.dropbox.com"

main :: IO ()
main = do
    args <- getArgs
    case args of
        [appKey, appSecret] -> mainProd appKey appSecret
        _ -> do
            hPutStrLn stderr "Usage: COMMAND app-key app-secret"
            exitFailure

mainProd = main_ DB.hostsDefault

mainDev = main_ hostsDev

mkConfig hosts appKey appSecret = do
    base <- DB.mkConfig DB.localeEn appKey appSecret DB.AccessTypeDropbox
    return $ base { DB.configHosts = hosts }

auth mgr config = liftIO $ do
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

accountInfo mgr session = liftIO $ do
    hPutStrLn stdout $ "---- Account Info ----"
    accountInfo <- DB.getAccountInfo mgr session
        `dieOnFailure` "Couldn't get account info"
    hPutStrLn stdout $ show accountInfo

rootMetadata mgr session = liftIO $ do
    hPutStrLn stdout $ "---- Root Folder ----"
    (DB.Meta meta extra, mContents) <- DB.getMetadataWithChildren mgr session "/" Nothing
        `dieOnFailure` "Couldn't get root folder listing"
    (hash, children) <- case mContents of
        Just (DB.FolderContents hash children) -> return (hash, children)
        _ -> die "Root is not a folder?  What the poop?"
    mapM_ ((hPutStrLn stdout).show) children
    hPutStrLn stdout $ "---- Root Folder (Again) ----"
    secondTime <- DB.getMetadataWithChildrenIfChanged mgr session "/" Nothing hash
        `dieOnFailure` "Couldn't get root folder listing again"
    hPutStrLn stdout (show secondTime) -- Will almost always print "Nothing" (i.e. "nothing has changed")

addFile mgr session = liftIO $ do
    hPutStrLn stdout $ "---- Add File ----"
    meta <- DB.putFile mgr session "/Facts.txt" DB.WriteModeAdd (DB.bsRequestBody $ C8.pack "Rian hates types.\n")
        `dieOnFailure` "Couldn't add Facts.txt"
    hPutStrLn stdout $ show meta

getFileContents mgr session = liftIO $ do
    hPutStrLn stdout $ "---- Get File ----"
    (meta, contents) <- DB.getFileBs mgr session "/Facts.txt" Nothing
        `dieOnFailure` "Couldn't read Facts.txt"
    hPutStrLn stdout $ show meta
    C8.hPutStrLn stdout contents

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
