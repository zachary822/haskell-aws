{-# LANGUAGE OverloadedStrings #-}

module Main where

import AWS.Auth (authenticateRequest)
import AWS.Config
import Data.Text qualified as T
import Network.HTTP.Conduit
import Network.HTTP.Simple
import System.Environment

main :: IO ()
main = do
  profile <- (T.pack <$>) <$> lookupEnv "AWS_PROFILE"
  creds <- loadConfig profile

  initReq <- parseRequest "https://sts.amazonaws.com/"

  req <-
    authenticateRequest
      creds
      "sts"
      True
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
