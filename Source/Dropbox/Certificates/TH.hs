{-# LANGUAGE TemplateHaskell #-}
{-# OPTIONS_GHC -fno-warn-missing-fields #-}

-- | Quasi quoters for parsing PEM files and PEM encoded X509 Certificates.
--
-- Whem using hardcoded certificates, be aware that a certificate may be revoked
-- at any time before it expires.
--
module Dropbox.Certificates.TH 
  ( pem
  , pemFile
  , x509
  , x509File
  ) where

import Data.ByteString.Char8 (pack)
import Data.ByteString.Lazy  (fromChunks)
import Data.PEM              (PEM(..), pemParseBS)
import Data.Certificate.X509 (X509(..), decodeCertificate)

import Language.Haskell.TH.Quote

rightsOrFirstLeft :: [Either a b] -> Either a [b]
rightsOrFirstLeft = foldr f (Right [])
    where
        f (Left e) _ = Left e
        f _ (Left e) = Left e
        f (Right v) (Right vs) = Right (v:vs)

pem :: QuasiQuoter
pem = QuasiQuoter { quoteExp = \s -> [| parsePem s |] }

pemFile :: QuasiQuoter
pemFile = quoteFile pem

parsePem :: String -> [PEM]
parsePem s = case pemParseBS $ pack s of
               Left err -> error $ "Failed to parse PEM file: " ++ err
               Right x -> x

x509 :: QuasiQuoter
x509 = QuasiQuoter { quoteExp = \s -> [| decodeCert . parsePem $ s |] } 

x509File :: QuasiQuoter
x509File = quoteFile x509

decodeCert :: [PEM] -> [X509]
decodeCert pems = 
    let es = [decodeCertificate (fromChunks [stuff]) | PEM _ _ stuff <- pems]
    in  case rightsOrFirstLeft es of
          Left err -> error $ "Failed to decode X509 file: " ++ err
          Right x509s -> x509s

