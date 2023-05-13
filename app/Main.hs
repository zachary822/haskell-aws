{-# LANGUAGE OverloadedStrings #-}

module Main where

import AWS.Auth
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
  initReq <- parseRequest "https://sts.amazonaws.com/"

  let req =
        initReq
          { method = "POST",
            requestBody = "Version=2011-06-15&Action=GetCallerIdentity",
            requestHeaders =
              [ ("Accept", "application/json"),
                ("Content-Type", "application/x-www-form-urlencoded")
              ]
          }
      authReq = authenticateRequest req now creds "sts"

  manager <- newManager tlsManagerSettings
  resp <- httpLbs authReq manager
  print resp
