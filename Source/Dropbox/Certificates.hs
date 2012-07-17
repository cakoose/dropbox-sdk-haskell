{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module Dropbox.Certificates 
  ( CertVerifierFunc
  , CertVerifier(..)
  , certVerifierInsecure
  , certVerifierFromPemFile
  , certVerifierFromRootCerts
  , certVerifierFromDbX509s
  ) where

import System.IO                       (withFile, IOMode(ReadMode))

import Data.ByteString                 (ByteString)
import qualified Data.ByteString       as B
import qualified Data.ByteString.Lazy  as LB
import qualified Data.ByteString.Char8 as B8

import           Data.PEM              (PEM(..))
import qualified Data.PEM              as PEM

import           Data.Certificate.X509 (X509)
import qualified Data.Certificate.X509 as X509

import           Data.Time.Clock       (UTCTime(utctDay), getCurrentTime)

import qualified Network.TLS           as TLS
import qualified Network.TLS.Extra     as TLSExtra

import Dropbox.Certificates.TH


dbX509s :: [X509]
dbX509s = [x509File|trusted-certs.crt|]

-- | Use the buildin Dropbox certificates.
certVerifierFromDbX509s :: CertVerifier
certVerifierFromDbX509s = CertVerifier "compiled in Dropbox certificates" (certVerifierFromRootCerts dbX509s)

----------------------------------------------------------------------
-- SSL Certificate Validation

type CertVerifierFunc =
    ByteString                     -- ^The server's host name.
    -> [X509]                      -- ^The server's certificate chain.
    -> IO TLS.TLSCertificateUsage  -- ^Whether the certificate chain is valid or not.

-- |How the server's SSL certificate will be verified.
data CertVerifier = CertVerifier
    { certVerifierName :: String           -- ^The human-friendly name of the policy (only for debug prints)
    , certVerifierFunc :: CertVerifierFunc -- ^The function that implements certificate validation.
    }

instance Show CertVerifier where
    show (CertVerifier name _) = "CertVerifier " ++ show name

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
certVerifierFromPemFile :: FilePath -> IO (Either String CertVerifier)
certVerifierFromPemFile filePath = do
    raw <- withFile filePath ReadMode B.hGetContents
    case PEM.pemParseBS raw of
        Left err -> return $ Left err
        Right pems -> do
            let es = [X509.decodeCertificate (LB.fromChunks [stuff]) | PEM _ _ stuff <- pems]
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

-- |A certificate validation routine.  It's in 'IO' to match what 'HTTP.Enumerator'
-- expects, but we don't actually do any I/O.
certVerifierFromRootCerts ::
    [X509]            -- ^The set of trusted root certificates.
    -> ByteString     -- ^The remote server's domain name.
    -> [X509]         -- ^The certificate chain provided by the remote server.
    -> IO TLS.TLSCertificateUsage
-- TODO: Rewrite this crappy code.  SSL cert checking needs to be more correct than this.
certVerifierFromRootCerts roots domain chain = do
        utcTime <- getCurrentTime
        let day = utctDay utcTime
        certAll
            [ return $ TLSExtra.certificateVerifyDomain (B8.unpack domain) chain
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

