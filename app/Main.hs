{-# LANGUAGE BinaryLiterals #-}
{-# OPTIONS_GHC -Wno-deferred-out-of-scope-variables #-}
{-# OPTIONS_GHC -Wno-missing-signatures #-}
{-# OPTIONS_GHC -Wno-name-shadowing #-}

module Main where

import Control.Monad
import Data.Binary.Get
import Data.Binary.Put
import Data.Bits
import qualified Data.ByteString as B
import Data.ByteString.Builder
import qualified Data.ByteString.Char8 as BS
import Data.ByteString.Conversion (toByteString')
import qualified Data.ByteString.Lazy as LBS
import Data.List (intercalate)
import Data.Word (Word16, Word32, Word8)
import Debug.Trace (traceShow, traceShowM)

-- dns packet = dns header: 12 bytes fixed
--            + dns question: variable
--            + dns answer: variable list of question
--            + authority section: variable list of dns record
--            + additional section: variable list of dns record
--
-- dns header = id: 2 bytes
--            + flags: 16 bits or 2 bytes
--            + no. of questions: 2 bytes
--            + no. of answers: 2 bytes
--            + no. of authorities: 2 bytes
--            + no. of entry in additional section: 2 bytes
--
-- dns question = name: encoded domain name
--              + type: 16 bit or 2 bytes
--              + class: 2 bytes

-- dns record = name: byteString
--            + type: 2 byte int
--            + class : 2 byte int
--            + ttl : 4 byte int
--            + record : 2 byte int

-- dns flag: QR:  1 bit Query Response
--           OPCODE: 4 bits Operation Code
--           AA: 1 bit Authoritative Answer
--           TC: 1 bit Truncated Message
--           RD: 1 bit Recursion Desired
--           RA: 1 bit  Recursion Available
--           Z: 3 bits Reserved
--           RCODE: 4 bits Response Code

data DNSHeader = DNSHeader
  { dnsHeaderId :: Data.Word.Word16, --  a 16 bit word or 2 bytes int
    dnsHeaderFlags :: Data.Word.Word16, -- QR OPCODE AA TC RD RA Z RCODE
    -- dnsHeaderFlagQR:: Bool,
    -- dnsHeaderFlagOPCODE:: Word4,
    -- dnsHeaderFlagAA:: Bool,
    -- dnsHeaderFlagTC:: Bool,
    -- dnsHeaderFlagRD:: Bool,
    -- dnsHeaderFlagRA:: Bool,
    -- dnsHeaderFlagZ:: Word4, -- 3 bit
    -- dnsHeaderFlagRCODE:: Word4,
    dnsHeaderNumQuestion :: Data.Word.Word16,
    dnsHeaderNumAnswer :: Data.Word.Word16,
    dnsHeaderNumAuthority :: Data.Word.Word16,
    dnsHeaderNumAdditional :: Data.Word.Word16
  }
  deriving (Show)

data DNSQuestion = DNSQuestion
  { dnsQuestionName :: BS.ByteString,
    dnsQuestionType :: Data.Word.Word16,
    dnsQuestionClass :: Data.Word.Word16
  }
  deriving (Show)

data DNSRecord = DNSRecord
  { dnsRecordName :: BS.ByteString,
    dnsRecordType :: Data.Word.Word16,
    dnsRecordClass :: Data.Word.Word16,
    dnsRecordTtl :: Data.Word.Word32,
    dnsRecordData :: BS.ByteString
  }
  deriving (Show)

data DNSPacket = DNSPacket
  { dnsPacketHeader :: DNSHeader,
    dnsPacketQuestions :: [DNSQuestion],
    dnsPacketAnswers :: [DNSRecord],
    dnsPacketAuthorities :: [DNSRecord],
    dnsPacketAdditionals :: [DNSRecord]
  }
  deriving (Show)

-----------------------------------------------------
headerToBytes :: DNSHeader -> BS.ByteString
headerToBytes header = BS.toStrict $ runPut $ do
  putWord16be (dnsHeaderId header)
  putWord16be (dnsHeaderFlags header)
  putWord16be (dnsHeaderNumQuestion header)
  putWord16be (dnsHeaderNumAnswer header)
  putWord16be (dnsHeaderNumAuthority header)
  putWord16be (dnsHeaderNumAdditional header)

questionToBytes :: DNSQuestion -> BS.ByteString
questionToBytes question = BS.toStrict $ runPut $ do
  putByteString (dnsQuestionName question)
  putWord16be (dnsQuestionType question)
  putWord16be (dnsQuestionClass question)

encodeDNSName :: String -> BS.ByteString
encodeDNSName domainName = toByteString' $ mconcat encodedParts <> word8 0
  where
    parts = splitByDot domainName
    encodedParts = map encodePart parts
    splitByDot :: String -> [String]
    splitByDot = words . map (\c -> if c == '.' then ' ' else c)
    encodePart :: String -> Builder
    encodePart part = word8 (fromIntegral $ length part) <> stringUtf8 part

-- A record
typeA :: Int
typeA = 1

typeNs :: Int
typeNs = 2

typeTxt :: Int
typeTxt = 16

classIn :: Data.Word.Word16
classIn = 1

encodeQuery :: String -> Data.Word.Word16 -> IO BS.ByteString
encodeQuery domainName recordType = do
  let _id = 1
      recursionDesired = 1 `Data.Bits.shiftL` 8
      -- flag is of 2 bytes = 16 bits  = max value 2^17 - 1
      -- recursionDesired = 0
      -- recursionDesired = (2 ^ 17) -1
      header = DNSHeader _id recursionDesired 1 0 0 0
      question = DNSQuestion (encodeDNSName domainName) recordType classIn
      queryBytes = headerToBytes header <> questionToBytes question
  return queryBytes

--------------------------------
getDNSHeader :: Get DNSHeader
getDNSHeader = DNSHeader <$> getWord16be <*> getWord16be <*> getWord16be <*> getWord16be <*> getWord16be <*> getWord16be

getDomainName :: BS.ByteString -> Get BS.ByteString
getDomainName input = do
  len <- getInt8
  let lengthValue = len .&. 63
  getDomainName' input len lengthValue
  where
    getDomainName' input len lengthValue
      | len == 0 = return BS.empty
      | isPointer len = do
          d <- getInt8
          let offset = fromIntegral $ lengthValue * 256 + fromIntegral d
          decodeCompressed offset input
      | otherwise = do
          label <- getByteString $ fromIntegral lengthValue
          rest <- getDomainName input
          return $
            if BS.null rest
              then label
              else label <> BS.pack "." <> rest
    decodeCompressed :: Int -> BS.ByteString -> Get BS.ByteString
    decodeCompressed offset input = do
      let msg = BS.drop offset input
      case runGetOrFail (getDomainName input) (LBS.fromStrict msg) of
        Left (_, _, err) -> traceShow ("err: " ++ show err) $ return BS.empty
        Right (_, _, domain) -> return domain
    isPointer c = testBit c 7 && testBit c 6

getDNSQuestionNE :: BS.ByteString -> Word16 -> Get [DNSQuestion]
getDNSQuestionNE input x = do
  replicateM (fromIntegral x) getDNSQuestion
  where
    getDNSQuestion :: Get DNSQuestion
    getDNSQuestion = DNSQuestion <$> getDomainName input <*> getWord16be <*> getWord16be

getDNSRecordList :: BS.ByteString -> Word16 -> Get [DNSRecord]
getDNSRecordList input count = do
  replicateM (fromIntegral count) getDNSRecord
  where
    getDNSRecord = do
      domain <- getDomainName input
      type' <- getWord16be
      class' <- getWord16be
      ttl <- getWord32be
      data_len <- getInt16be
      data_ <- getRecordData (fromIntegral type') (fromIntegral data_len)
      return $ DNSRecord {dnsRecordName = domain, dnsRecordType = type', dnsRecordClass = class', dnsRecordTtl = ttl, dnsRecordData = data_}
    getRecordData :: Int -> Int -> Get BS.ByteString
    getRecordData type_ data_len
      | type_ == typeNs = getDomainName input
      | type_ == typeA = do
          ipBytes <- getByteString $ fromIntegral data_len
          return $ BS.pack $ ipToString $ B.unpack ipBytes
      | otherwise = getByteString $ fromIntegral data_len
    ipToString :: [Word8] -> String
    ipToString = intercalate "." . map show

getDNSPacket :: BS.ByteString -> Get DNSPacket
getDNSPacket input = do
  header <- getDNSHeader
  questions <- getDNSQuestionNE input (dnsHeaderNumQuestion header)
  answers <- getDNSRecordList input (dnsHeaderNumAnswer header)
  authorities <- getDNSRecordList input (dnsHeaderNumAuthority header)
  additionals <- getDNSRecordList input (dnsHeaderNumAdditional header)
  return $ DNSPacket header questions answers authorities additionals

-- Main function to parse a ByteString into a DNSPacket
decodeQuery :: BS.ByteString -> Either String DNSPacket
decodeQuery bs =
  case runGetOrFail (getDNSPacket bs) (LBS.fromStrict bs) of
    Left (_, _, err) -> Left err
    Right (_, _, dnsPacket) -> Right dnsPacket

readByteStringFromFile :: FilePath -> IO BS.ByteString
readByteStringFromFile filePath = do
  BS.readFile filePath

ipBytes :: BS.ByteString
ipBytes = B.pack [66, 67]

ipList :: [Word8]
ipList = ipBytesToList ipBytes

ipBytesToList :: BS.ByteString -> [Word8]
ipBytesToList = B.unpack

main :: IO ()
main = do
  byteString <- readByteStringFromFile "output_file.bin"
  case decodeQuery byteString of
    Left err -> putStrLn $ "Error parsing DNS packet: " ++ err
    Right domain -> print domain

-- Right domain -> print ""

-- {-
--   in one terminal listen on 1053 as a dns resolver
--   nc -u -l 1053 >! query_packet.txt
--   run dig to send dns packet to localhost
--   dig +retry=0 -4 -p 1053 @127.0.0.1 +noedns +noall +noanswer +noauthority +noadditional google.com
--   run our resolver
--   cabal run > my_query.txt
--   content of query_packet.txt and my_query.txt would be similar except starting packet ID
--   ID is of type word16 so 16 bit unsigned = 2 bytes

--  header -> 00 45 00 00 00 01 00 00 00 00 00 00 -> 12 bytes
--  id = 00 45
--  query  -> 03 77 77 77 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 00 01 00 01

--  when we try to resolve google.com it is of type A (ipv4) or type AAAA (ipv6)
--  but when we try to resolve www.google.com it is of type CNAME as it doesnt map IP but another DNS record google.com in this case
-- -}
