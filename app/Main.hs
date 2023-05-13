{-# LANGUAGE OverloadedStrings #-}

module Main where

import AWS
  ( AWSCredentials
      ( AWSCredentials,
        awsAccessKeyId,
        awsRegion,
        awsSecretAccessKey
      ),
    authenticateRequest,
  )
import Data.Time (getCurrentTime)
import Network.HTTP.Conduit
import System.Environment

main :: IO ()
main = do
  region <- getEnv "AWS_DEFAULT_REGION"
  awsId <- getEnv "AWS_ACCESS_KEY_ID"
  awsSecret <- getEnv "AWS_SECRET_ACCESS_KEY"

  let creds =
        AWSCredentials
          { awsRegion = region,
            awsAccessKeyId = awsId,
            awsSecretAccessKey = awsSecret
          }

  now <- getCurrentTime
  initReq <- parseRequest "https://sts.amazonaws.com/?Version=2011-06-15&Action=GetCallerIdentity"

  let req =
        initReq
          { method = "GET",
            requestBody = "",
            requestHeaders =
              [ ("Accept", "application/json")
              ]
          }
      authReq = authenticateRequest req now creds "sts"

  manager <- newManager tlsManagerSettings
  resp <- httpLbs authReq manager
  print resp
