{-# LANGUAGE OverloadedStrings #-}

module Main where

import AWS.Auth (authenticateRequest)
import AWS.Config
import Data.Time (getCurrentTime)
import Network.HTTP.Conduit
import System.Environment

main :: IO ()
main = do
  profile <- lookupEnv "AWS_PROFILE"
  creds <- loadConfig profile

  now <- getCurrentTime
  initReq <- parseRequest "https://sts.amazonaws.com/"

  let req =
        initReq
          { method = "POST"
          , requestBody = "Version=2011-06-15&Action=GetCallerIdentity"
          , requestHeaders =
              [ ("Accept", "application/json")
              , ("Content-Type", "application/x-www-form-urlencoded")
              ]
          }
      authReq = authenticateRequest req now creds "sts"

  manager <- newManager tlsManagerSettings
  resp <- httpLbs authReq manager
  print resp
