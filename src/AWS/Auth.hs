{-# LANGUAGE OverloadedStrings #-}

module AWS.Auth where

import Crypto.Hash (Digest, SHA256, hash)
import Crypto.MAC.HMAC (hmac, hmacGetDigest)
import Data.ByteArray (convert)
import Data.ByteArray.Encoding (Base (Base16), convertToBase)
import Data.ByteString as B (ByteString, toStrict)
import Data.ByteString.Char8 qualified as C
import Data.CaseInsensitive qualified as CI
import Data.List (intersperse, sortBy)
import Data.Ord (comparing)
import Data.Time.Clock (UTCTime)
import Data.Time.Format (defaultTimeLocale, formatTime)
import Network.HTTP.Conduit
import Network.HTTP.Simple (Header, addRequestHeader, getRequestQueryString)
import Network.HTTP.Types.URI (urlEncode)

data AWSCredentials = AWSCredentials
  { awsRegion :: String
  , awsAccessKeyId :: String
  , awsSecretAccessKey :: String
  }
  deriving (Show)

getBody :: Request -> ByteString
getBody req =
  case requestBody req of
    RequestBodyBS b -> b
    RequestBodyLBS b -> B.toStrict b
    _ -> error "not supported"

canonicalRequest :: Request -> ByteString
canonicalRequest req =
  C.concat $
    intersperse
      "\n"
      [ method req
      , path req
      , canonicalQueryString req
      , canonicalHeaders req
      , signedHeaders req
      , hexHash (getBody req)
      ]

headers :: Request -> [Header]
headers req = sortBy (comparing fst) (("host", host req) : requestHeaders req)

canonicalHeaders :: Request -> ByteString
canonicalHeaders req =
  C.concat . map prepareHeader $ headers req
 where
  prepareHeader (name, value) = CI.foldCase (CI.original name) <> ":" <> value <> "\n"

hexHash :: ByteString -> ByteString
hexHash p = convertToBase Base16 $ (hash p :: Digest SHA256)

signedHeaders :: Request -> ByteString
signedHeaders req =
  C.concat . intersperse ";" . map (CI.foldCase . CI.original . fst) $ headers req

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
    [ "AWS4-HMAC-SHA256\n"
    , C.pack (formatAmzDate date)
    , "\n"
    , C.pack (formatDate date)
    , "/"
    , region
    , "/"
    , service
    , "/aws4_request\n"
    , hashConReq
    ]

formatDate :: UTCTime -> String
formatDate = formatTime defaultTimeLocale "%Y%m%d"

formatAmzDate :: UTCTime -> String
formatAmzDate = formatTime defaultTimeLocale "%Y%m%dT%H%M%SZ"

createSignature ::
  -- | Canonical Request
  ByteString ->
  -- | Current time
  UTCTime ->
  -- | Secret Access Key
  ByteString ->
  -- | AWS region
  ByteString ->
  -- | AWS service
  ByteString ->
  ByteString
createSignature canReq now key region service = v4Signature dKey toSign
 where
  canonicalReqHash = hexHash canReq
  toSign = stringToSign now region service canonicalReqHash
  dKey = v4DerivedKey key (C.pack $ formatDate now) region service

v4Signature :: ByteString -> ByteString -> ByteString
v4Signature derivedKey payLoad = convertToBase Base16 $ hmacSHA256 derivedKey payLoad

authenticateRequest :: Request -> UTCTime -> AWSCredentials -> String -> Request
authenticateRequest req now creds service =
  datedReq
    { requestHeaders =
        authHeader now (C.pack $ awsAccessKeyId creds) (signedHeaders datedReq) sig (C.pack $ awsRegion creds) bservice
          : requestHeaders datedReq
    }
 where
  datedReq = addRequestHeader "x-amz-date" (C.pack $ formatAmzDate now) req
  canReq = canonicalRequest datedReq
  bservice = C.pack service
  sig = createSignature canReq now (C.pack $ awsSecretAccessKey creds) (C.pack $ awsRegion creds) bservice

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
  ( "Authorization"
  , C.concat
      [ "AWS4-HMAC-SHA256 Credential="
      , sId
      , "/"
      , C.pack (formatDate now)
      , "/"
      , region
      , "/"
      , service
      , "/aws4_request, SignedHeaders="
      , signHeads
      , ", Signature="
      , sig
      ]
  )

canonicalQueryString :: Request -> ByteString
canonicalQueryString req = C.concat . intersperse "&" . map formatQueryParam . sortBy (comparing fst) $ getRequestQueryString req
 where
  formatQueryParam (key, Just value) = key <> "=" <> urlEncode True value
  formatQueryParam (key, Nothing) = key <> "="
