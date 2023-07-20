{-# LANGUAGE OverloadedStrings #-}

module AWS.Config where

import AWS.Auth
import Control.Monad.Trans.Class
import Control.Monad.Trans.Except
import Data.Ini
import Data.Text qualified as T
import System.Directory
import System.Environment

readConfigFile :: FilePath -> ExceptT String IO Ini
readConfigFile = ExceptT . readIniFile

loadConfigFiles :: ExceptT String IO (Ini, Ini)
loadConfigFiles = do
  homeDir <- lift getHomeDirectory
  config <- readConfigFile (homeDir ++ "/.aws/config")
  credentials <- readConfigFile (homeDir ++ "/.aws/credentials")
  return (config, credentials)

getRegion :: Maybe String -> (Ini, Ini) -> IO String
getRegion profile (config, _) =
  lookupEnv "AWS_DEFAULT_REGION" >>= maybe (getConfigRegion profile config) return

getConfigRegion :: Maybe String -> Ini -> IO String
getConfigRegion profile config =
  either fail (return . T.unpack) $ lookupValue (T.pack section) "region" config
 where
  section = maybe "default" ("profile " <>) profile

getAwsId :: Maybe String -> (Ini, Ini) -> IO String
getAwsId profile config =
  lookupEnv "AWS_ACCESS_KEY_ID" >>= maybe (getConfigAwsId profile config) return

getConfigAwsId :: Maybe String -> (Ini, Ini) -> IO String
getConfigAwsId profile (_, credentials) =
  either fail (return . T.unpack) $ lookupValue (maybe "default" T.pack profile) "aws_access_key_id" credentials

getAwsSecret :: Maybe String -> (Ini, Ini) -> IO String
getAwsSecret profile config =
  lookupEnv "AWS_SECRET_ACCESS_KEY" >>= maybe (getConfigAwsSecret profile config) return

getConfigAwsSecret :: Maybe String -> (Ini, Ini) -> IO String
getConfigAwsSecret profile (_, credentials) =
  either fail (return . T.unpack) $ lookupValue (maybe "default" T.pack profile) "aws_secret_access_key" credentials

loadConfig :: Maybe String -> IO AWSCredentials
loadConfig profile = do
  configs <- either fail return =<< runExceptT loadConfigFiles
  AWSCredentials
    <$> getRegion profile configs
    <*> getAwsId profile configs
    <*> getAwsSecret profile configs
