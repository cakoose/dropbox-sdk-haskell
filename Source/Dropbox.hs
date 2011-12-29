module Dropbox (
    -- * Configuration
    mkConfig,
    Config(..),
    CertVerifier(..),
    certVerifierInsecure,
    certVerifierFromPemFile,
    certVerifierFromRootCerts,
    AppId(..),
    Hosts(..),
    hostsDefault,
    Locale,
    localeEn, localeEs, localeFr, localeDe, localeJp,
    AccessType(..),
    -- * Manager
    Manager,
    withManager,
    -- * OAuth
    RequestToken(..),
    authStart,
    AccessToken(..),
    authFinish,
    Session(..),
    -- * Get user account info
    getAccountInfo, AccountInfo(..),
    -- * Basic file access API
    -- ** Get metadata
    getMetadata, getMetadataWithChildren, getMetadataWithChildrenIfChanged,
    Meta(..), MetaBase(..), MetaExtra(..), FolderContents(..), FileExtra(..),
    FolderHash(..), FileRevision(..),
    -- ** Uploading files
    addFile, forceFile, updateFile,
    -- * Common data types
    fileRevisionToString, folderHashToString,
    ErrorMessage, URL, Path,
    RequestBody, bsRequestBody
) where

{-
TODO:
- The JSON we get from the server sometimes has numbers encoded as strings
  Make sure we handle that case.
- Proper return values for 404, 406, oauth unlinked, etc.
-}

import Network.HTTP.Base (urlEncode)
import qualified Data.ByteString.UTF8 as UTF8 (toString, fromString)
import qualified Data.URLEncoded as URLEncoded
import qualified Network.URI as URI
import Data.URLEncoded (URLEncoded)
import qualified Text.JSON as JSON
import Text.JSON (JSON, readJSON, showJSON)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Char8 as BS8
import Data.Word (Word64)
import Data.Int (Int64)
import Data.List (isPrefixOf)
import Data.Time.Clock (UTCTime(utctDay), getCurrentTime)
import Data.Time.Format (parseTime, formatTime)
import System.Locale (defaultTimeLocale)
import Control.Monad (liftM)
import qualified Data.Enumerator as E
import qualified Data.Enumerator.List as EL
import qualified Network.HTTP.Enumerator as HE
import qualified Network.HTTP.Types as HT
import qualified Network.TLS as TLS
import qualified Network.TLS.Extra as TLSExtra
import Data.Certificate.X509 (X509)
import qualified Data.Certificate.X509 as X509
import Data.Certificate.PEM as PEM
import Data.Enumerator (Iteratee, Enumerator)
import qualified Blaze.ByteString.Builder.ByteString as BlazeBS
import System.IO as IO
import qualified Paths_dropbox_sdk as Paths

type ErrorMessage = String
type URL = String

-- |Dropbox file and folder paths.  Should always start with "/".
type Path = String

apiVersion = "1"

-- |The type of folder access your Dropbox application uses (<https://www.dropbox.com/developers/start/core>).
data AccessType
    = AccessTypeDropbox   -- ^Full access to the user's entire Dropbox
    | AccessTypeAppFolder -- ^Access to an application-specific "app folder" within the user's Dropbox
    deriving (Show, Eq)

-- |Your application's Dropbox "app key" and "app secret".
data AppId = AppId String String deriving (Show, Eq)

-- |An OAuth request token (returned by 'authStart')
data RequestToken = RequestToken String String deriving (Show, Eq)

-- |An OAuth request token (returned by 'authFinish', used to construct a 'Session')
data AccessToken = AccessToken String String deriving (Show, Eq)

accessTypePath :: AccessType -> String
accessTypePath AccessTypeDropbox = "dropbox"
accessTypePath AccessTypeAppFolder = "sandbox"

accessTypeRoot :: AccessType -> String
accessTypeRoot AccessTypeDropbox = "dropbox"
accessTypeRoot AccessTypeAppFolder = "app_folder"

-- |The set of hosts that serve the Dropbox API.  Just use 'hostsDefault'.
data Hosts = Hosts
    { hostsWeb :: String         -- ^The Dropbox API web host (for OAuth step 2)
    , hostsApi :: String         -- ^The Dropbox API endpoint for most non-content-transferring calls.
    , hostsApiContent :: String  -- ^The Dropbox API endpoint for most content-transferring calls.
    } deriving (Show, Eq)

-- |The standard set of hosts that serve the Dropbox API.  Used to create a 'Config'.
hostsDefault :: Hosts
hostsDefault = Hosts
    { hostsWeb = "www.dropbox.com"
    , hostsApi = "api.dropbox.com"
    , hostsApiContent = "api-content.dropbox.com"
    }

-- |Specifies a locale (the string is a two-letter locale code)
newtype Locale = Locale String deriving (Show, Eq)

-- |The English (American) locale ("en").
localeEn :: Locale
localeEn = Locale "en"

-- |The Spanish locale (@'Locale' "es"@).
localeEs :: Locale
localeEs = Locale "es"

-- |The French locale (Locale "fr").
localeFr :: Locale
localeFr = Locale "fr"

-- |The German locale (Locale "de").
localeDe :: Locale
localeDe = Locale "de"

-- |The Japanese locale (Locale "jp").
localeJp :: Locale
localeJp = Locale "jp"

-- |The configuration used to make authentication calls and API calls.  You typically create
-- one of these via the 'config' helper function.
data Config = Config
    { configHosts :: Hosts           -- ^The hosts to connect to (just use 'hostsDefault').
    , configUserLocale :: Locale     -- ^The locale that the Dropbox service should use when returning user-visible strings.
    , configAppId :: AppId           -- ^Your app's key/secret
    , configAccessType :: AccessType -- ^The type of folder access your Dropbox application uses.
    , configCertVerifier :: CertVerifier -- ^The server certificate validation routine.
    } deriving (Show)

type CertVerifierFunc =
    HT.Ascii                       -- ^The server's host name.
    -> [X509]                      -- ^The server's certificate chain.
    -> IO TLS.TLSCertificateUsage  -- ^Whether the certificate chain is valid or not.

-- |How the server's SSL certificate will be verified.
data CertVerifier = CertVerifier
    { certVerifierName :: String -- ^The human-friendly name of the policy (only for debug prints)
    , certVerifierFunc :: CertVerifierFunc -- ^The function that implements certificate validation.
    }

instance Show CertVerifier where
    show (CertVerifier name _) = "CertVerifier " ++ show name

-- |A convenience function that constructs a 'Config'
mkConfig ::
    Locale
    -> String      -- ^Your Dropbox app key
    -> String      -- ^Your Dropbox app secret
    -> AccessType  -- ^'configAccessType'
    -> IO Config
mkConfig userLocale appKey appSecret accessType = do
    caFile <- Paths.getDataFileName "trusted-certs.crt"
    vf <- do
        r <- certVerifierFromPemFile caFile
        case r of
            Right vf -> return $ vf
            Left err -> fail $ "Unable to load root certificates from " ++ (show caFile) ++ ": " ++ err
    return $ Config
        { configHosts = hostsDefault
        , configUserLocale = userLocale
        , configAppId = AppId appKey appSecret
        , configAccessType = accessType
        , configCertVerifier = vf
        }

-- |Contains a 'Config' and an 'AccessToken'.  Every API call (after OAuth is complete)
-- requires this as an argument.
data Session = Session
    { sessionConfig :: Config
    , sessionAccessToken :: AccessToken  -- ^The 'AccessToken' obtained from 'authFinish'
    }

----------------------------------------------------------------------
-- SSL Certificate Validation

-- |A dummy implementation that doesn't perform any verification.
certVerifierInsecure :: CertVerifier
certVerifierInsecure = CertVerifier "insecure" (\_ _ -> return TLS.CertificateUsageAccept)

rightsOrFirstLeft :: [Either a b] -> Either a [b]
rightsOrFirstLeft = foldr f (Right [])
    where
        f (Left e) _ = Left e
        f _ (Left e) = Left e
        f (Right v) (Right vs) = Right (v:vs)

-- |Reads certificates in PEM format from the given file and uses those as the roots when
-- verifying certificates.  This function basically just loads the certificates and delegates
-- to 'certVerifierFromRootCerts' for the actual checking.
certVerifierFromPemFile :: FilePath -> IO (Either ErrorMessage CertVerifier)
certVerifierFromPemFile filePath = do
    raw <- withFile filePath IO.ReadMode BS.hGetContents
    let pems = PEM.parsePEMs raw
    let es = [X509.decodeCertificate (LBS.fromChunks [stuff]) | (_, stuff) <- pems]
    case rightsOrFirstLeft es of
        Left err -> return $ Left err
        Right x509s -> return $ Right $ CertVerifier ("PEM file: " ++ show filePath) (certVerifierFromRootCerts x509s)

certAll :: [IO TLS.TLSCertificateUsage] -> IO TLS.TLSCertificateUsage
certAll [] = return TLS.CertificateUsageAccept
certAll (head:rest) = do
    r <- head
    case r of
        TLS.CertificateUsageAccept -> certAll rest
        reject -> return $ reject

-- |Given a set of root certificates, yields a certificate validation function.
certVerifierFromRootCerts ::
    [X509]            -- ^The set of trusted root certificates.
    -> HT.Ascii       -- ^The remove server's domain name.
    -> [X509]         -- ^The certificate chain provided by the remote server.
    -> IO TLS.TLSCertificateUsage
-- TODO: Rewrite this crappy code.  SSL cert checking needs to be more correct than this.
certVerifierFromRootCerts roots domain chain = do
        utcTime <- getCurrentTime
        let day = utctDay utcTime
        certAll
            [ return $ TLSExtra.certificateVerifyDomain (BS8.unpack domain) chain
            , checkTrustChain day chain
            ]
    where
        checkTrustChain _ [] = return $ TLS.CertificateUsageReject $ TLS.CertificateRejectOther "empty chain"
        checkTrustChain day (head:rest) = do
            if isUnexpired day head
                then do
                    issuerMatch <- mapM (head `isIssuedBy`) roots
                    if any (== True) issuerMatch
                        then return $ TLS.CertificateUsageAccept
                        else case rest of
                            [] -> return $ TLS.CertificateUsageReject TLS.CertificateRejectUnknownCA
                            (next:_) -> do
                                nextOk <- TLSExtra.certificateVerifyAgainst head next
                                if nextOk
                                    then checkTrustChain day rest
                                    else return $ TLS.CertificateUsageReject $ TLS.CertificateRejectOther "break in verification chain"
                else return $ TLS.CertificateUsageReject $ TLS.CertificateRejectExpired
        isIssuedBy :: X509 -> X509 -> IO Bool
        isIssuedBy c issuer =
            if subjectDN issuer == issuerDN c
                then TLSExtra.certificateVerifyAgainst c issuer
                else return False
        subjectDN c = X509.certSubjectDN $ X509.x509Cert c
        issuerDN c = X509.certIssuerDN $ X509.x509Cert c
        isUnexpired day cert =
            let ((beforeDay, _, _), (afterDay, _, _)) = X509.certValidity (X509.x509Cert cert)
            in beforeDay < day && day <= afterDay

----------------------------------------------------------------------
-- Authentication/Authorization

buildOAuthHeaderNoToken (AppId consumerKey consumerSecret) =
    "OAuth oauth_version=\"1.0\", oauth_signature_method=\"PLAINTEXT\""
    ++ ", oauth_consumer_key=\"" ++ urlEncode consumerKey ++ "\""
    ++ ", oauth_signature=\"" ++ sig ++ "\""
    where
        sig = urlEncode consumerSecret ++ "&"

buildOAuthHeader (AppId consumerKey consumerSecret) (signingKey, signingSecret) =
    "OAuth oauth_version=\"1.0\", oauth_signature_method=\"PLAINTEXT\""
    ++ ", oauth_consumer_key=\"" ++ urlEncode consumerKey ++ "\""
    ++ ", oauth_token=\"" ++ urlEncode signingKey ++ "\""
    ++ ", oauth_signature=\"" ++ sig ++ "\""
    where
        sig = urlEncode consumerSecret ++ "&" ++ urlEncode signingSecret

-- |OAuth step 1.  If successful, returns a 'RequestToken' (to be used with
-- 'authFinish' eventually) and an authorization URL that you should redirect the user
-- to next.  If you provide a callback URL (optional), then the authorization URL you
-- send the user to will redirect to your callback URL after the user authorizes your
-- application.
authStart ::
    Manager      -- ^The HTTP connection manager to use.
    -> Config
    -> Maybe URL -- ^The callback URL (optional)
    -> IO (Either ErrorMessage (RequestToken, URL))
authStart mgr config callback = do
    result <- httpClientGet mgr vf uri oauthHeader (mkHandler handler)
    return $ mergeLefts result
    where
        Locale locale = configUserLocale config
        host = hostsApi (configHosts config)
        webHost = hostsWeb (configHosts config)
        consumerPair = configAppId config
        uri = "https://" ++ host ++ ":443/" ++ apiVersion ++ "/oauth/request_token?locale=" ++ urlEncode locale
        oauthHeader = buildOAuthHeaderNoToken consumerPair
        vf = certVerifierFunc $ configCertVerifier config
        handler 200 _ body = do
            let sBody = UTF8.toString body  -- toString should return a Maybe, but it doesn't.  You too, Haskell?
            case parseTokenParts sBody of
                Left err -> Left $ "couldn't understand response from Dropbox: " ++ err
                Right requestToken@(RequestToken requestTokenKey _) -> do
                    let authorizeUrl = "https://" ++ webHost ++ "/"++apiVersion++"/oauth/authorize?locale=" ++ urlEncode locale ++ "&oauth_token=" ++ urlEncode requestTokenKey ++ callbackSuffix
                    Right (requestToken, authorizeUrl)
        handler code reason body = Left $ "server returned " ++ show code ++ ": " ++ show reason ++ ": " ++ show body
        callbackSuffix = case callback of
            Nothing -> ""
            Just callbackUrl -> "&oauth_callback=" ++ urlEncode callbackUrl
        parseTokenParts :: String -> Either String RequestToken
        parseTokenParts s = do
            enc <- URLEncoded.importString s
            key <- requireKey enc "oauth_token"
            secret <- requireKey enc "oauth_token_secret"
            return $ RequestToken key secret

-- |OAuth step 3.  Once you've directed the user to the authorization URL from 'authStart'
-- and the user has authorized your app, call this function to get a 'RequestToken', which
-- is used to make Dropbox API calls.
authFinish ::
    Manager       -- ^The HTTP connection manager to use.
    -> Config
    -> RequestToken  -- ^The 'RequestToken' obtained from 'authStart'
    -> IO (Either ErrorMessage (AccessToken, String))
        -- ^The 'AccessToken' used to make Dropbox API calls and the user's Dropbox user ID.
authFinish mgr config (RequestToken rtKey rtSecret) = do
    result <- httpClientGet mgr vf uri oauthHeader (mkHandler handler)
    return $ mergeLefts result
    where
        host = hostsApi (configHosts config)
        (Locale locale) = configUserLocale config
        consumerPair = configAppId config
        uri = "https://" ++ host ++ ":443/"++apiVersion++"/oauth/access_token?locale=" ++ urlEncode locale
        oauthHeader = buildOAuthHeader consumerPair (rtKey, rtSecret)
        vf = certVerifierFunc $ configCertVerifier config
        handler 200 _ body = do
            let sBody = UTF8.toString body  -- toString should return a Maybe, but it doesn't.  You too, Haskell?
            case parseResponse sBody of
                Left err -> Left $ "couldn't understand response from Dropbox: " ++ err
                Right value -> Right value
        handler code reason body = Left $ "server returned " ++ show code ++ ": " ++ show reason ++ ": " ++ show body
        parseResponse :: String -> Either String (AccessToken, String)
        parseResponse s = do
            enc <- URLEncoded.importString s
            key <- requireKey enc "oauth_token"
            secret <- requireKey enc "oauth_token_secret"
            userId <- requireKey enc "uid"
            return $ (AccessToken key secret, userId)

requireKey :: URLEncoded -> String -> Either String String
requireKey enc name = case URLEncoded.lookup name enc of
    Just value -> return value
    Nothing -> Left $ "missing parameter \"" ++ name ++ "\""

----------------------------------------------------------------------

dbTimeFormat = "%a, %d %b %Y %H:%M:%S %z"

dbFormatTime = formatTime defaultTimeLocale dbTimeFormat
dbParseTime = parseTime defaultTimeLocale dbTimeFormat

-- JSON parse helpers
readJsonFieldT :: JSON a => String -> [(String, JSON.JSValue)] -> b -> (a -> b) -> JSON.Result b
readJsonFieldT a as d t = case lookup a as of
    Just jv -> do
        v <- readJSON jv
        return (t v)
    Nothing -> JSON.Ok d

readJsonFieldD :: JSON a => String -> [(String, JSON.JSValue)] -> a -> JSON.Result a
readJsonFieldD a as d = readJsonFieldT a as d id

readJsonField :: JSON a => String -> [(String, JSON.JSValue)] -> JSON.Result a
readJsonField a as = maybe (fail $ "missing field \"" ++ a ++ "\"") return (lookup a as) >>= readJSON

handleJsonBodyT :: JSON a => (a -> b) -> ByteString -> Either ErrorMessage b
handleJsonBodyT tf body = case JSON.decode $ UTF8.toString body of
    JSON.Ok v -> Right (tf v)
    JSON.Error err -> Left $ "couldn't parse response from Dropbox: " ++ err

handleJsonBody :: JSON a => ByteString -> Either ErrorMessage a
handleJsonBody = handleJsonBodyT id

----------------------------------------------------------------------
-- GetAccountInfo

-- |Information about a user account.
data AccountInfo = AccountInfo
    { accountInfoUid :: Word64            -- ^Dropbox user ID
    , accountInfoDisplayName :: String    -- ^Full name (when displayed as a single string)
    , accountInfoCountry :: Maybe String  -- ^Two-letter country code, if available
    , accountInfoReferralUrl :: String    -- ^Dropbox referral link
    , accountInfoQuota :: Quota           -- ^Information about the storage quota
    } deriving (Show, Eq)

data Quota = Quota
    { quotaTotal :: Word64    -- ^Total space allocation (bytes)
    , quotaNormal :: Word64   -- ^Space used outside of shared folders (bytes)
    , quotaShared :: Word64   -- ^Space used in shared folders (bytes)
    } deriving (Show, Eq)

instance JSON AccountInfo where
    showJSON a = JSON.makeObj
        [ ("uid", showJSON $ accountInfoUid a)
        , ("display_name", showJSON $ accountInfoDisplayName a)
        , ("country", showJSON $ accountInfoCountry a)
        , ("referral_link", showJSON $ accountInfoReferralUrl a)
        , ("quota_info", showJSON $ accountInfoQuota a)
        ]
    readJSON (JSON.JSObject obj) = do
        uid <- readJsonField "uid" m
        displayName <- readJsonField "display_name" m
        country <- readJsonFieldT "country" m Nothing Just
        referralUrl <- readJsonField "referral_link" m
        quota <- readJsonField "quota_info" m
        return $ AccountInfo
            { accountInfoUid = uid
            , accountInfoDisplayName = displayName
            , accountInfoCountry = country
            , accountInfoReferralUrl = referralUrl
            , accountInfoQuota = quota
            }
        where m = JSON.fromJSObject obj
    readJSON _ = fail "expecting an object"

instance JSON Quota where
    showJSON q = JSON.makeObj
        [ ("quota", showJSON $ quotaTotal q)
        , ("normal", showJSON $ quotaNormal q)
        , ("shared", showJSON $ quotaShared q)
        ]
    readJSON (JSON.JSObject obj) = do
        total <- readJsonField "quota" m
        normal <- readJsonField "normal" m
        shared <- readJsonField "shared" m
        return $ Quota
            { quotaTotal = total
            , quotaNormal = normal
            , quotaShared = shared
            }
        where m = JSON.fromJSObject obj
    readJSON _ = fail "expecting an object"

-- |Retrieve information about the user account your 'AccessToken' is connected to.
getAccountInfo ::
    Manager     -- ^The HTTP connection manager to use.
    -> Session
    -> IO (Either ErrorMessage AccountInfo)
getAccountInfo mgr session = do
    result <- doGet mgr session hostsApi "account/info" [] (mkHandler handler)
    return $ mergeLefts result
    where
        handler 200 _ body = handleJsonBody body
        handler code reason body = Left $ "non-200 response from Dropbox (" ++ (show code) ++ ":" ++ reason ++ ": " ++ (show body) ++ ")"

----------------------------------------------------------------------
-- Metadata JSON

-- |The metadata for a file or folder.  'MetaBase' contains the metadata common to
-- files and folders.  'MetaExtra' contains the file-specific or folder-specific data.
data Meta = Meta MetaBase MetaExtra
    deriving (Eq, Show)

-- |Metadata common to both files and folders.
data MetaBase = MetaBase
    { metaRoot :: AccessType  -- ^Matches the 'AccessType' of the app that retrieved the metadata.
    , metaPath :: String      -- ^The full path (starting with a "/") of the file or folder, relative to 'metaRoot'
    , metaIsDeleted :: Bool   -- ^Whether this metadata entry refers to a file that had been deleted when the entry was retrieved.
    , metaThumbnail :: Bool   -- ^Will be @True@ if this file might have a thumbnail, and @False@ if it definitely doesn't.
    , metaIcon :: String      -- ^The name of the icon used to illustrate this file type in Dropbox's icon library (<https://www.dropbox.com/static/images/dropbox-api-icons.zip>).
    } deriving (Eq, Show)

-- |Metadata that's specific to either files or folders.
data MetaExtra
    = File FileExtra    -- ^Files have additional metadata
    | Folder            -- ^Folders do not
    deriving (Eq, Show)

-- |Represents a file's revision ('fileRevision').
newtype FileRevision = FileRevision String deriving (Eq, Show)
fileRevisionToString (FileRevision s) = s

-- |Extra metadata specific to files (and not folders)
data FileExtra = FileExtra
    { fileBytes :: Integer         -- ^The file size (bytes)
    , fileHumanSize :: String      -- ^A human-readable representation of the file size, for example "15 bytes" (localized according to 'Locale' in 'Config')
    , fileRevision :: FileRevision -- ^The revision of the file
    , fileModified :: UTCTime      -- ^When this file was added or last updated
    } deriving (Eq, Show)

-- |Represents an identifier for a folder's metadata and contents.  Can be used with
-- 'getMetadataWithChildrenIfChanged' to avoid downloading a folder's metadata and contents
-- if it hasn't changed.
newtype FolderHash = FolderHash String deriving (Eq, Show)
folderHashToString (FolderHash s) = s

-- |The single-level contents of a folder.
data FolderContents = FolderContents
    { folderHash :: FolderHash  -- ^An identifier for the folder's metadata and contents.
    , folderChildren :: [Meta]  -- ^The metadata for the immediate children of a folder.
    } deriving (Eq, Show)

-- Used internally to parse out a metadata for a folder that also includes a child list.
newtype MetaWithChildren = MetaWithChildren (Meta, Maybe FolderContents)
removeMetaChildren (MetaWithChildren (meta, _)) = meta
addMetaChildren meta = MetaWithChildren (meta, Nothing)

instance JSON Meta where
    showJSON = showJSON.addMetaChildren
    readJSON = (liftM removeMetaChildren).readJSON

instance JSON MetaWithChildren where
    showJSON (MetaWithChildren (Meta base extra, maybeContents)) = JSON.makeObj (baseFields ++ extraFields ++ contentsFields)
        where
            baseFields =
                [ ("root", showJSON $ accessTypeRoot $ metaRoot base)
                , ("path", showJSON $ metaPath base)
                , ("is_deleted", showJSON $ metaIsDeleted base)
                , ("thumb_exists", showJSON $ metaThumbnail base)
                , ("icon", showJSON $ metaIcon base)
                ]
            extraFields = case extra of
                File f ->
                    [ ("bytes", showJSON $ fileBytes f)
                    , ("size", showJSON $ fileHumanSize f)
                    , ("rev", showJSON $ fileRevisionToString $ fileRevision f)
                    , ("modified", showJSON $ dbFormatTime $ fileModified f)
                    ]
                Folder -> []
            contentsFields = case maybeContents of
                Just fc ->
                    [ ("hash", showJSON $ folderHashToString $ folderHash fc)
                    , ("contents", showJSON $ map addMetaChildren (folderChildren fc))
                    ]
                Nothing -> []

    readJSON (JSON.JSObject obj) = do
        rootStr :: String <- readJsonField "root" m
        root <- case rootStr of
            "app_folder" -> return AccessTypeAppFolder
            "dropbox" -> return AccessTypeDropbox
            _ -> fail ("expecting \"app_folder\" or \"dropbox\", instead got: " ++ show rootStr)
        path <- readJsonField "path" m
        isDeleted <- readJsonFieldD "is_deleted" m False
        thumbnail <- readJsonField "thumb_exists" m
        icon <- readJsonField "icon" m
        let base = MetaBase {
              metaRoot = root
            , metaPath = path
            , metaIsDeleted = isDeleted
            , metaThumbnail = thumbnail
            , metaIcon = icon
            }
        isFolder <- readJsonField "is_dir" m
        (extra, contents) <- if isFolder
            then do
                hash <- readJsonFieldD "hash" m ""
                children <- readJsonFieldD "contents" m []
                return $ (Folder, Just FolderContents
                    { folderHash = FolderHash hash
                    , folderChildren = (map removeMetaChildren children)
                    })
            else do
                bytes <- readJsonField "bytes" m
                humanSize <- readJsonField "size" m
                revision <- readJsonField "rev" m
                modifiedStr <- readJsonField "modified" m
                modified <- case dbParseTime modifiedStr of
                    Just utcTime -> return utcTime
                    Nothing -> fail "invalid date/time format"
                return $ (File FileExtra
                    { fileBytes = bytes
                    , fileHumanSize = humanSize
                    , fileRevision = FileRevision revision
                    , fileModified = modified
                    }, Nothing)
        return $ MetaWithChildren (Meta base extra, contents)
        where
            m = JSON.fromJSObject obj
    readJSON _ = fail "expecting an object"

----------------------------------------------------------------------
-- GetMetadata

-- |Get the metadata for the file or folder at the given path.
getMetadata ::
    Manager    -- ^The HTTP connection manager to use.
    -> Session
    -> Path      -- ^The full path (relative to your 'DbAccessType' root)
    -> IO (Either ErrorMessage Meta)
getMetadata mgr session path = do
    if "/" `isPrefixOf` path
        then do
            result <- doGet mgr session hostsApi url params (mkHandler handler)
            return $ mergeLefts result
        else return $ Left $ "path must start with \"/\""
    where
        at = accessTypePath $ configAccessType (sessionConfig session)
        url = "metadata/" ++ at ++ path
        params = [("list", "false")]
        handler 200 _ body = handleJsonBody body
        handler code reason body = Left $ "non-200 response from Dropbox (" ++ (show code) ++ ":" ++ reason ++ ": " ++ (show body) ++ ")"

-- |Get the metadata for the file or folder at the given path.  If it's a folder,
-- return the first-level folder contents' metadata entries as well.
getMetadataWithChildren ::
    Manager    -- ^The HTTP connection manager to use.
    -> Session
    -> Path      -- ^The full path (relative to your 'DbAccessType' root)
    -> Maybe Integer
        -- ^A limit on folder contents (max: 10,000).  If the path refers to a folder and this folder
        -- has more than the specified number of immediate children, the entire
        -- 'getMetadataWithChildren' call will fail with an HTTP 406 error code.  If unspecified, or
        -- if set to zero, the server will set this to 10,000.
    -> IO (Either ErrorMessage (Meta, Maybe FolderContents))
getMetadataWithChildren mgr session path childLimit = do
    if "/" `isPrefixOf` path
        then do
            result <- doGet mgr session hostsApi url params (mkHandler handler)
            return $ mergeLefts result
        else return $ Left $ "'path' must start with \"/\""
    where
        at = accessTypePath $ configAccessType (sessionConfig session)
        url = "metadata/" ++ at ++ path
        params = [("list", "true")] ++ case childLimit of
            Just l -> [("file_limit", show l)]
            Nothing -> []
        handler 200 _ body = handleJsonBodyT (\(MetaWithChildren v) -> v) body
        handler code reason body = Left $ "non-200 response from Dropbox (" ++ (show code) ++ ":" ++ reason ++ ": " ++ (show body) ++ ")"

-- |Same as 'getMetadataWithChildren' except it'll return @Nothing@ if the 'FolderHash'
-- of the folder on Dropbox is the same as the 'FolderHash' passed in.
getMetadataWithChildrenIfChanged ::
    Manager           -- ^The HTTP connection manager to use.
    -> Session
    -> Path
    -> Maybe Integer
    -> FolderHash
        -- ^For folders, the returned child metadata will include a 'folderHash' field that
        -- is a short identifier for the current state of the folder.  If the 'FolderHash'
        -- for the specified path hasn't change, this call will return @Nothing@, which
        -- indicates that the previously-retrieved metadata is still the latest.
    -> IO (Either ErrorMessage (Maybe (Meta, Maybe FolderContents)))
getMetadataWithChildrenIfChanged mgr session path childLimit (FolderHash hash) = do
    if "/" `isPrefixOf` path
        then do
            result <- doGet mgr session hostsApi url params (mkHandler handler)
            return $ mergeLefts result
        else return $ Left $ "'path' must start with \"/\""
    where
        at = accessTypePath $ configAccessType (sessionConfig session)
        url = "metadata/" ++ at ++ path
        params = [("list", "true"), ("hash", hash)] ++ case childLimit of
            Just l -> [("file_limit", show l)]
            Nothing -> []
        handler 200 _ body = handleJsonBodyT (\(MetaWithChildren v) -> Just v) body
        handler 304 _ _ = Right Nothing
        handler code reason body = Left $ "non-200 response from Dropbox (" ++ (show code) ++ ":" ++ reason ++ ": " ++ (show body) ++ ")"

----------------------------------------------------------------------
-- AddFile/ForceFile/UpdateFile

-- |Add a new file.  If a file or folder already exists at the given path, your
-- file will be automatically renamed.  If successful, you'll get back the metadata
-- for your newly-uploaded file.
addFile ::
    Manager    -- ^The HTTP connection manager to use.
    -> Session
    -> Path        -- ^The full path (relative to your 'DbAccessType' root)
    -> RequestBody -- ^The file contents.
    -> IO (Either ErrorMessage Meta)
addFile mgr session path contents = putFile mgr session path contents [("overwrite", "false")]

-- |Overwrite a file, assuming it is the version you expect.  Specify the version
-- you expect with the 'FileRevision'.  If the file on Dropbox matches the given
-- revision, the file will be replaced with the contents you specify.  If the file
-- on Dropbox doesn't have the specified revision, it will be left alone and your
-- file will be automatically renamed.  If successful, you'll get back the metadata
-- for your newly-uploaded file.
updateFile ::
    Manager    -- ^The HTTP connection manager to use.
    -> Session
    -> Path         -- ^The full path (relative to your 'DbAccessType' root)
    -> RequestBody  -- ^The file contents.
    -> FileRevision -- ^The revision of the file you expect to be writing to.
    -> IO (Either ErrorMessage Meta)
updateFile mgr session path contents (FileRevision rev) =
    putFile mgr session path contents [("parent_rev", rev)]

-- |Add a file.  If a file already exists at the given path, that file will
-- be overwritten.  If successful, you'll get back the metadata for your
-- newly-uploaded file.
forceFile ::
    HE.Manager     -- ^The 'Network.HTTP.Enumerator.Manager' to use.
    -> Session
    -> Path        -- ^The full path (relative to your 'DbAccessType' root)
    -> RequestBody -- ^The file contents.
    -> IO (Either ErrorMessage Meta)
forceFile mgr session path contents = putFile mgr session path contents [("overwrite", "true")]

----------------------------------------------------------------------
-- The underlying "put_file" call.

putFile ::
    HE.Manager
    -> Session
    -> Path
    -> RequestBody
    -> [(String,String)]
    -> IO (Either ErrorMessage Meta)
putFile mgr session path contents params =
    if "/" `isPrefixOf` path
        then do
            result <- doPut mgr session hostsApiContent url params contents (mkHandler handler)
            return $ mergeLefts result
        else return $ Left $ "path must start with \"/\""
    where
        at = accessTypePath $ configAccessType (sessionConfig session)
        url = "files_put/" ++ at ++ path
        handler 200 _ body = handleJsonBody body
        handler code reason body = Left $ "non-200 response from Dropbox (" ++ (show code) ++ ":" ++ reason ++ ": " ++ (show body) ++ ")"

----------------------------------------------------------------------

-- very low level uri generator, handles proper escaping
generateDropboxURI' :: Bool -> String -> String -> Int -> String -> [(String, String)] -> String
generateDropboxURI' escapePath proto host port path params = URI.uriToString id (URLEncoded.addToURI (URLEncoded.importList params) (URI.URI proto (Just $ URI.URIAuth "" host $ ":" ++ show port) path' "" "")) ""
  where path' = if escapePath then (URI.escapeURIString URI.isAllowedInURI path) else path

prepRequest :: Session -> (Hosts -> String) -> String -> [(String, String)] -> (String, String)
prepRequest (Session config (AccessToken atKey atSecret)) hostSelector path params = (uri, oauthHeader)
    where
        host = hostSelector (configHosts config)
        (Locale locale) = configUserLocale config
        consumerPair = configAppId config
        uri = generateDropboxURI' False "https:" host 443 ("/" ++ apiVersion ++ "/" ++ path) (("locale", locale) : params)
        oauthHeader = buildOAuthHeader consumerPair (atKey, atSecret)

doPut ::
    Manager
    -> Session
    -> (Hosts -> String)
    -> String
    -> [(String,String)]
    -> RequestBody
    -> Handler r
    -> IO (Either ErrorMessage r)
doPut mgr session hostSelector path params requestBody handler = do
    let (uri, oauthHeader) = prepRequest session hostSelector path params
    let vf = certVerifierFunc $ configCertVerifier $ sessionConfig session
    httpClientPut mgr vf uri oauthHeader handler requestBody

doGet ::
    Manager
    -> Session
    -> (Hosts -> String)
    -> String
    -> [(String,String)]
    -> Handler r
    -> IO (Either ErrorMessage r)
doGet mgr session hostSelector path params handler = do
    let (uri, oauthHeader) = prepRequest session hostSelector path params
    let vf = certVerifierFunc $ configCertVerifier $ sessionConfig session
    httpClientGet mgr vf uri oauthHeader handler

----------------------------------------------------------------------

type Manager = HE.Manager

withManager :: (Manager -> IO r) -> IO r
withManager = HE.withManager

----------------------------------------------------------------------

type SimpleHandler r = Int -> String -> ByteString -> r

-- |HTTP response-handling function.
type Handler r = HT.Status -> HT.ResponseHeaders -> (Iteratee ByteString IO r)

-- |An HTTP request body: an 'Int64' for the length and an 'Enumerator'
-- that yields the actual data.
data RequestBody = RequestBody Int64 (forall r. Enumerator ByteString IO r)

-- |Create a 'RequestBody' from a single 'ByteString'
bsRequestBody :: ByteString -> RequestBody
bsRequestBody bs = RequestBody length (E.enumLists [[bs]])
    where
        length = fromInteger $ toInteger $ BS.length bs

mkHandler :: SimpleHandler r -> Handler r
mkHandler sh (HT.Status code reason) _headers = do
    bs <- bsIteratee
    return $ sh code (BS8.unpack reason) bs

mergeLefts :: Either a (Either a b) -> Either a b
mergeLefts v = case v of
    Left a -> Left a
    Right r -> r

-- |An 'Iteratee' that reads in 'ByteString' chunks and constructs one concatenated 'ByteString'
bsIteratee :: Monad m => Iteratee ByteString m ByteString
bsIteratee = do
    chunks <- EL.consume
    return $ BS.concat chunks

httpClientDo ::
    Manager
    -> HT.Ascii
    -> RequestBody
    -> CertVerifierFunc
    -> URL
    -> String
    -> Handler r
    -> IO (Either String r)
httpClientDo mgr method (RequestBody len bsEnum) vf url oauthHeader handler =
    case HE.parseUrl url of
        Just baseReq -> do
            let req = baseReq {
                HE.secure = True,
                HE.method = method,
                HE.requestHeaders = headers,
                HE.requestBody = HE.RequestBodyEnum len builderEnum,
                HE.checkCerts = vf }
            resp <- E.run_ $ HE.http req handler mgr
            return $ Right resp
        Nothing -> do
            return $ Left $ "bad URL: " ++ show url
    where
        headers = [("Authorization", UTF8.fromString oauthHeader)]
        builderEnum = E.joinE bsEnum (EL.map BlazeBS.fromByteString)

httpClientGet :: Manager -> CertVerifierFunc -> URL -> String -> Handler r -> IO (Either String r)
httpClientGet mgr vf url oauthHeader handler = httpClientDo mgr "GET" (bsRequestBody BS.empty) vf url oauthHeader handler

httpClientPut :: Manager -> CertVerifierFunc -> URL -> String -> Handler r -> RequestBody -> IO (Either String r)
httpClientPut mgr vf url oauthHeader handler requestBody = httpClientDo mgr "PUT" requestBody vf url oauthHeader handler
