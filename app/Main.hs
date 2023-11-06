{-# OPTIONS_GHC -Wno-deferred-out-of-scope-variables #-}

module Main where

import Data.Binary.Put
import Data.Bits (Bits (shiftL))
import Data.ByteString.Builder
import qualified Data.ByteString.Char8 as BS
import Data.ByteString.Conversion (toByteString')
import Data.List.NonEmpty as NE hiding (length, map)
import Data.Word

-- dns packet = dns header 
--            + dns question 
--            + dns answer (list of dns record) 
--            + authority section (list of dns record) 
--            + additional section (list of dns record)

data DNSHeader = DNSHeader
  { dnsHeaderId :: Word16,
    dnsHeaderFlags :: Word16,
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
    dnsRecordType :: Int,
    dnsRecordClass :: Int,
    dnsRecordTtl :: Int,
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
  let _id = 69
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
