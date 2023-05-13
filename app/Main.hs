{-# LANGUAGE OverloadedStrings #-}

module Main where

import Crypto.Hash (Digest, SHA256, hash)
import Crypto.MAC.HMAC (hmac, hmacGetDigest)
import Data.ByteArray (convert)
import Data.ByteString as B (ByteString, dropWhile, toStrict)
import Data.ByteString.Base16 qualified as Base16 (encode)
import Data.ByteString.Char8 qualified as C
import Data.CaseInsensitive qualified as CI
import Data.Char (toLower)
import Data.List (intersperse, sortBy)
import Data.Ord (comparing)
import Data.Time (getCurrentTime)
import Data.Time.Clock (UTCTime)
import Data.Time.Format (defaultTimeLocale, formatTime)
import Network.HTTP.Conduit
import Network.HTTP.Simple (Header)
import System.Environment

getBody :: Request -> ByteString
getBody req =
  case body of
    RequestBodyBS b -> b
    RequestBodyLBS b -> B.toStrict b
  where
    body = requestBody req

canonicalRequest :: Request -> ByteString
canonicalRequest req =
  C.concat $
    intersperse
      "\n"
      [ method req,
        path req,
        B.dropWhile (== 63) (queryString req),
        canonicalHeaders req,
        signedHeaders req,
        hexHash (getBody req)
      ]

headers :: Request -> [Header]
headers req = sortBy (comparing fst) (("host", host req) : requestHeaders req)

canonicalHeaders :: Request -> ByteString
canonicalHeaders req =
  C.concat $ map (\(hn, hv) -> bsToLower (CI.original hn) <> ":" <> hv <> "\n") hs
  where
    hs = headers req

hexHash :: ByteString -> ByteString
hexHash p = Base16.encode . convert $ (hash p :: Digest SHA256)

bsToLower :: ByteString -> ByteString
bsToLower = C.map toLower

signedHeaders :: Request -> ByteString
signedHeaders req =
  C.concat . intersperse ";" $ map (bsToLower . CI.original . fst) hs
  where
    hs = headers req

v4DerivedKey ::
  -- | AWS Secret Access Key
  ByteString ->
  -- | Date in YYYYMMDD format
  ByteString ->
  -- | AWS region
  ByteString ->
  -- | AWS service
  ByteString ->
  ByteString
v4DerivedKey secretAccessKey date region service = hmacSHA256 kService "aws4_request"
  where
    kDate = hmacSHA256 ("AWS4" <> secretAccessKey) date
    kRegion = hmacSHA256 kDate region
    kService = hmacSHA256 kRegion service

hmacSHA256 :: ByteString -> ByteString -> ByteString
hmacSHA256 key p = convert (hmacGetDigest $ hmac key p :: Digest SHA256)

stringToSign ::
  -- | current time
  UTCTime ->
  -- | The AWS region
  ByteString ->
  -- | The AWS service
  ByteString ->
  -- | Hashed canonical request
  ByteString ->
  ByteString
stringToSign date region service hashConReq =
  C.concat
    [ "AWS4-HMAC-SHA256\n",
      C.pack (formatAmzDate date),
      "\n",
      C.pack (formatDate date),
      "/",
      region,
      "/",
      service,
      "/aws4_request\n",
      hashConReq
    ]

formatDate :: UTCTime -> String
formatDate = formatTime defaultTimeLocale "%Y%m%d"

formatAmzDate :: UTCTime -> String
formatAmzDate = formatTime defaultTimeLocale "%Y%m%dT%H%M%SZ"

createSignature ::
  -- | Http request
  Request ->
  -- | Current time
  UTCTime ->
  -- | Secret Access Key
  ByteString ->
  -- | AWS region
  ByteString ->
  -- | AWS service
  ByteString ->
  ByteString
createSignature req now key region service = v4Signature dKey toSign
  where
    canReqHash = hexHash $ canonicalRequest req
    toSign = stringToSign now region service canReqHash
    dKey = v4DerivedKey key (C.pack $ formatDate now) region service

v4Signature :: ByteString -> ByteString -> ByteString
v4Signature derivedKey payLoad = Base16.encode $ hmacSHA256 derivedKey payLoad

authenticateRequest :: Request -> UTCTime -> ByteString -> ByteString -> ByteString -> ByteString -> Request
authenticateRequest req now sid key region service =
  req
    { requestHeaders = authHeader now sid (signedHeaders req) sig region service : requestHeaders req
    }
  where
    sig = createSignature req now key region service

authHeader ::
  -- | Current time
  UTCTime ->
  -- | Secret access key
  ByteString ->
  -- | Signed headers
  ByteString ->
  -- | Signature
  ByteString ->
  -- | AWS Region
  ByteString ->
  -- | AWS Service
  ByteString ->
  Header
authHeader now sId signHeads sig region service =
  ( "Authorization",
    C.concat
      [ "AWS4-HMAC-SHA256 Credential=",
        sId,
        "/",
        C.pack (formatDate now),
        "/",
        region,
        "/",
        service,
        "/aws4_request, SignedHeaders=",
        signHeads,
        ", Signature=",
        sig
      ]
  )

main :: IO ()
main = do
  awsId <- C.pack <$> getEnv "AWS_ACCESS_KEY_ID"
  awsSecret <- C.pack <$> getEnv "AWS_SECRET_ACCESS_KEY"

  let body = ""
  let reqBody = RequestBodyBS body

  now <- getCurrentTime
  initReq <- parseRequest "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"
  let req =
        initReq
          { method = "GET",
            requestBody = reqBody,
            requestHeaders =
              [ ("Accept", "application/json"),
                ("x-amz-date", C.pack $ formatAmzDate now)
              ]
          }
      authReq = authenticateRequest req now awsId awsSecret "us-east-1" "sts"

  manager <- newManager tlsManagerSettings
  resp <- httpLbs authReq manager
  print resp

-- T.putStr $ T.toStrict . decodeUtf8 . responseBody $ res
