{-# LANGUAGE OverloadedStrings #-}

module AWS.S3 where

import AWS.Auth
import Data.ByteString.Lazy (ByteString)
import Data.String
import Network.HTTP.Conduit
import Network.HTTP.Simple

uploadS3 :: AWSCredentials -> String -> String -> FilePath -> IO (Response ByteString)
uploadS3 creds bucket key path = do
  req <-
    setRequestMethod "PUT"
      <$> parseRequest ("https://" <> bucket <> ".s3.amazonaws.com")

  httpLBS
    =<< ( authenticateRequest creds "s3" False
            . setRequestPath ("/" <> fromString key)
            . setRequestBodyFile path
        )
      req
        { method = "PUT"
        , requestHeaders = ("Content-Type", "multipart/form-data") : requestHeaders req
        }
