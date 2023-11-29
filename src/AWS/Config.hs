{-# LANGUAGE OverloadedStrings #-}

module AWS.Config (loadConfig) where

import AWS.Auth
import Control.Monad.Trans.Class
import Control.Monad.Trans.Except
import Control.Monad.Trans.Maybe
import Data.Functor ((<&>))
import Data.Ini
import Data.Maybe
import Data.Text (Text, pack)
import System.Directory
import System.Environment
import System.FilePath

type Profile = Maybe Text
type ConfigFiles = (Ini, Ini)

lookupEnvText :: String -> MaybeT IO Text
lookupEnvText e = lift (lookupEnv e) >>= hoistMaybe <&> pack

readConfigFile :: FilePath -> ExceptT String IO Ini
readConfigFile = ExceptT . readIniFile

loadConfigFiles :: ExceptT String IO ConfigFiles
loadConfigFiles = do
  homeDir <- lift getHomeDirectory
  config <- readConfigFile (homeDir </> ".aws/config")
  credentials <- readConfigFile (homeDir </> ".aws/credentials")
  return (config, credentials)

getRegion :: Profile -> ConfigFiles -> IO Text
getRegion profile (config, _) =
  runMaybeT (lookupEnvText "AWS_DEFAULT_REGION") >>= maybe (getConfigRegion profile config) return

getConfigRegion :: Profile -> Ini -> IO Text
getConfigRegion profile config =
  either fail return $ lookupValue section "region" config
 where
  section = "profile " <> fromMaybe "default" profile

getAwsId :: Profile -> (Ini, Ini) -> IO Text
getAwsId profile config =
  runMaybeT (lookupEnvText "AWS_ACCESS_KEY_ID") >>= maybe (getConfigAwsId profile config) return

getConfigAwsId :: Profile -> (Ini, Ini) -> IO Text
getConfigAwsId profile (_, credentials) =
  either fail return $ lookupValue (fromMaybe "default" profile) "aws_access_key_id" credentials

getAwsSecret :: Profile -> (Ini, Ini) -> IO Text
getAwsSecret profile config =
  runMaybeT (lookupEnvText "AWS_SECRET_ACCESS_KEY") >>= maybe (getConfigAwsSecret profile config) return

getConfigAwsSecret :: Profile -> (Ini, Ini) -> IO Text
getConfigAwsSecret profile (_, credentials) =
  either fail return $ lookupValue (fromMaybe "default" profile) "aws_secret_access_key" credentials

loadConfig :: Profile -> IO AWSCredentials
loadConfig profile = do
  configs <- either fail return =<< runExceptT loadConfigFiles
  AWSCredentials
    <$> getRegion profile configs
    <*> getAwsId profile configs
    <*> getAwsSecret profile configs
