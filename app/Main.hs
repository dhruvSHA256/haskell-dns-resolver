{-# OPTIONS_GHC -Wno-deferred-out-of-scope-variables #-}
{-# OPTIONS_GHC -Wno-name-shadowing #-}

module Main where

import Control.Monad
import Data.Binary.Get
import Data.Binary.Put
import Data.Bits (Bits (shiftL), (.&.))
import Data.ByteString.Builder
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Char8 as C
import Data.ByteString.Conversion (toByteString')
import qualified Data.ByteString.Lazy as LBS
import Data.List.NonEmpty as NE hiding (length, map)
import Data.Word

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
    dnsPacketQuestions :: NE.NonEmpty DNSQuestion,
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
typeA :: Data.Word.Word16
typeA = 1

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
getDomainName :: Get BS.ByteString
getDomainName = do
  lengthByte <- getWord8
  if lengthByte == 0
    then return BS.empty
    else
      if lengthByte .&. 0xc0 /= 0
        then decodeCompressedName lengthByte
        else do
          label <- getByteString (fromIntegral lengthByte)
          rest <- getDomainName
          return $
            if BS.null rest
              then label
              else label <> C.pack "." <> rest

decodeCompressedName :: Word8 -> Get BS.ByteString
decodeCompressedName lengthByte = do
  pointerBytes <- getWord8
  let pointer = (lengthByte .&. 0x3f) `shiftL` 8 + fromIntegral pointerBytes
  currentPos <- bytesRead
  _ <- skip $ fromIntegral pointer
  result <- getDomainName
  _ <- skip $ fromIntegral (currentPos - fromIntegral pointer - 2) -- Adjust the current position
  return result

getDNSHeader :: Get DNSHeader
getDNSHeader = DNSHeader <$> getWord16be <*> getWord16be <*> getWord16be <*> getWord16be <*> getWord16be <*> getWord16be

getDNSQuestionNE :: Word16 -> Get (NonEmpty DNSQuestion)
getDNSQuestionNE x = do
  qs <- replicateM (fromIntegral x) getDNSQuestion
  case qs of
    [] -> error "No DNS questions read"
    (y : ys) -> return $ y :| ys
  where
    getDNSQuestion :: Get DNSQuestion
    getDNSQuestion = DNSQuestion <$> getDomainName <*> getWord16be <*> getWord16be

getDNSRecordList :: Word16 -> Get [DNSRecord]
getDNSRecordList count = do
  replicateM (fromIntegral count) getDNSRecord
  where
    getDNSRecord :: Get DNSRecord
    getDNSRecord = DNSRecord <$> getDomainName <*> getWord16be <*> getWord16be <*> getWord32be <*> getByteStringLenPrefix

getDNSPacket :: Get DNSPacket
getDNSPacket = do
  header <- getDNSHeader
  questions <- getDNSQuestionNE (dnsHeaderNumQuestion header)
  answers <- getDNSRecordList (dnsHeaderNumAnswer header)
  authorities <- getDNSRecordList (dnsHeaderNumAuthority header)
  additionals <- getDNSRecordList (dnsHeaderNumAdditional header)
  return $ DNSPacket header questions answers authorities additionals

getByteStringLenPrefix :: Get BS.ByteString
getByteStringLenPrefix = do
  len <- getWord8
  getByteString (fromIntegral len)

-- Main function to parse a ByteString into a DNSPacket
decodeQuery :: BS.ByteString -> Either String DNSPacket
decodeQuery bs =
  case runGetOrFail getDNSPacket (LBS.fromStrict bs) of
    Left (_, _, err) -> Left err
    Right (_, _, dnsPacket) -> Right dnsPacket

readByteStringFromFile :: FilePath -> IO BS.ByteString
readByteStringFromFile filePath = do
  BS.readFile filePath

main :: IO ()
main = do
  print "reading from file"
  byteString <- readByteStringFromFile "request.txt"
  print $ BS.length byteString
  case decodeQuery byteString of
    Left err -> putStrLn $ "Error parsing DNS packet: " ++ err
    Right dnsPacket -> print dnsPacket

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
