{-# LANGUAGE OverloadedStrings #-}

module AWS.Auth where

import Crypto.Hash (Digest, SHA256, hash)
import Crypto.MAC.HMAC (hmac, hmacGetDigest)
import Data.ByteArray (ByteArrayAccess)
import Data.ByteArray.Encoding (Base (Base16), convertToBase)
import Data.ByteString as B (ByteString, toStrict)
import Data.ByteString.Char8 qualified as C
import Data.CaseInsensitive qualified as CI
import Data.List (intersperse, sortBy)
import Data.Ord (comparing)
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8)
import Data.Time.Clock (UTCTime, getCurrentTime)
import Data.Time.Format (defaultTimeLocale, formatTime)
import Network.HTTP.Conduit
import Network.HTTP.Simple (Header, addRequestHeader, getRequestQueryString)
import Network.HTTP.Types.URI (urlEncode)

data AWSCredentials = AWSCredentials
  { awsRegion :: Text
  , awsAccessKeyId :: Text
  , awsSecretAccessKey :: Text
  }
  deriving (Show)

awsHmacSha256 :: ByteString
awsHmacSha256 = "AWS4-HMAC-SHA256"

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
hexHash p = convertToBase Base16 (hash p :: Digest SHA256)

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
  Digest SHA256
v4DerivedKey secretAccessKey date region service = hmacSHA256 kService ("aws4_request" :: ByteString)
 where
  kDate = hmacSHA256 ("AWS4" <> secretAccessKey) date
  kRegion = hmacSHA256 kDate region
  kService = hmacSHA256 kRegion service

hmacSHA256 :: (ByteArrayAccess k, ByteArrayAccess m) => k -> m -> Digest SHA256
hmacSHA256 key p = hmacGetDigest $ hmac key p

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
    [ awsHmacSha256
    , "\n"
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

v4Signature :: (ByteArrayAccess k, ByteArrayAccess m) => k -> m -> ByteString
v4Signature derivedKey payLoad = convertToBase Base16 $ hmacSHA256 derivedKey payLoad

authenticateRequest' :: UTCTime -> AWSCredentials -> Text -> Request -> Request
authenticateRequest' now creds service req =
  datedReq
    { requestHeaders =
        authHeader now key (signedHeaders datedReq) sig region serv
          : requestHeaders datedReq
    }
 where
  datedReq = addRequestHeader "x-amz-date" (C.pack $ formatAmzDate now) req
  canReq = canonicalRequest datedReq
  serv = encodeUtf8 service
  region = encodeUtf8 $ awsRegion creds
  key = encodeUtf8 $ awsAccessKeyId creds
  secret = encodeUtf8 $ awsSecretAccessKey creds
  sig = createSignature canReq now secret region serv

authenticateRequest :: AWSCredentials -> Text -> Request -> IO Request
authenticateRequest creds service req = do
  now <- getCurrentTime
  return $ authenticateRequest' now creds service req

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
      [ awsHmacSha256
      , " Credential="
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

formatQueryParam :: (ByteString, Maybe ByteString) -> ByteString
formatQueryParam (key, Just value) = key <> "=" <> urlEncode True value
formatQueryParam (key, Nothing) = key <> "="

canonicalQueryString :: Request -> ByteString
canonicalQueryString req = C.concat . intersperse "&" . map formatQueryParam . sortBy (comparing fst) $ getRequestQueryString req
