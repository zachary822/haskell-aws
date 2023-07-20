{-# LANGUAGE OverloadedStrings #-}

module Main where

import AWS.Auth (authenticateRequest)
import AWS.Config
import Data.Time (getCurrentTime)
import Network.HTTP.Conduit
import Network.HTTP.Simple
import System.Environment
import Data.Text qualified as T

main :: IO ()
main = do
  profile <- fmap T.pack <$> lookupEnv "AWS_PROFILE"
  creds <- loadConfig profile

  now <- getCurrentTime
  initReq <- parseRequest "https://sts.amazonaws.com/"

  let req =
        authenticateRequest
          now
          creds
          "sts"
          initReq
            { method = "POST"
            , requestBody = "Version=2011-06-15&Action=GetCallerIdentity"
            , requestHeaders =
                [ ("Accept", "application/json")
                , ("Content-Type", "application/x-www-form-urlencoded")
                ]
            }

  resp <- httpLBS req
  print resp
