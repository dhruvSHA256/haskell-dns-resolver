{-# OPTIONS_GHC -Wno-deferred-out-of-scope-variables #-}

module Main where

import Data.Binary.Put
import Data.Bits (Bits (shiftL))
import Data.ByteString.Builder
import qualified Data.ByteString.Char8 as BS
import Data.ByteString.Conversion (toByteString')
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
  { dnsHeaderId :: Word16, --  a 16 bit word or 2 bytes int
    dnsHeaderFlags :: Word16, -- QR OPCODE AA TC RD RA Z RCODE
    -- dnsHeaderFlagQR:: Bool,
    -- dnsHeaderFlagOPCODE:: Word4,
    -- dnsHeaderFlagAA:: Bool,
    -- dnsHeaderFlagTC:: Bool,
    -- dnsHeaderFlagRD:: Bool,
    -- dnsHeaderFlagRA:: Bool,
    -- dnsHeaderFlagZ:: Word4, -- 3 bit
    -- dnsHeaderFlagRCODE:: Word4,
    dnsHeaderNumQuestion :: Word16,
    dnsHeaderNumAnswer :: Word16,
    dnsHeaderNumAuthority :: Word16,
    dnsHeaderNumAdditional :: Word16
  }
  deriving (Show)

data DNSQuestion = DNSQuestion
  { dnsQuestionName :: BS.ByteString,
    dnsQuestionType :: Word16,
    dnsQuestionClass :: Word16
  }
  deriving (Show)

data DNSRecord = DNSRecord
  { dnsRecordName :: BS.ByteString,
    dnsRecordType :: Word16,
    dnsRecordClass :: Word16,
    dnsRecordTtl :: Word32,
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

myHeader :: DNSHeader
myHeader = DNSHeader 1 2 3 4 5 6

-----------------------------------------------------
headerToBytes :: DNSHeader -> BS.ByteString
headerToBytes header = BS.toStrict $ runPut $ do
  putWord16be (dnsHeaderId header)
  putWord16be (dnsHeaderFlags header)
  -- putWord16be (dnsHeaderFlagQR header)
  -- putWord16be (dnsHeaderFlagOPCODE header)
  -- putWord16be (dnsHeaderFlagAA header)
  -- putWord16be (dnsHeaderFlagTC header)
  -- putWord16be (dnsHeaderFlagRD header)
  -- putWord16be (dnsHeaderFlagRA header)
  -- putWord16be (dnsHeaderFlagZ header)
  -- putWord16be (dnsHeaderFlagRCODE header)
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

typeA :: Word16
typeA = 1

classIn :: Word16
classIn = 1

buildQuery :: String -> Word16 -> IO BS.ByteString
buildQuery domainName recordType = do
  let _id = 1
      recursionDesired = 1 `shiftL` 8
      -- flag is of 2 bytes = 16 bits  = max value 2^17 - 1
      -- recursionDesired = 0
      -- recursionDesired = (2 ^ 17) -1
      header = DNSHeader _id recursionDesired 1 0 0 0
      question = DNSQuestion (encodeDNSName domainName) recordType classIn
      queryBytes = headerToBytes header <> questionToBytes question
  return queryBytes

main :: IO ()
main = do
  q <- buildQuery "www.google.com" typeA
  BS.putStr q

{-
  in one terminal listen on 1053 as a dns resolver
  nc -u -l 1053 >! query_packet.txt
  run dig to send dns packet to localhost
  dig +retry=0 -4 -p 1053 @127.0.0.1 +noedns +noall +noanswer +noauthority +noadditional google.com
  run our resolver
  cabal run > my_query.txt
  content of query_packet.txt and my_query.txt would be similar except starting packet ID
  ID is of type word16 so 16 bit unsigned = 2 bytes

 header -> 00 45 00 00 00 01 00 00 00 00 00 00 -> 12 bytes
 id = 00 45
 query  -> 03 77 77 77 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 00 01 00 01

 when we try to resolve google.com it is of type A (ipv4) or type AAAA (ipv6)
 but when we try to resolve www.google.com it is of type CNAME as it doesnt map IP but another DNS record google.com in this case
-}
