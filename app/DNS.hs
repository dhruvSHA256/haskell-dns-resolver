module DNS where

import qualified Data.ByteString.Char8 as BS
import Data.Word (Word16, Word32)

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
--            + class: 2 byte int
--            + ttl: 4 byte int
--            + record: 2 byte int

-- dns flag: QR:  1 bit Query Response
--           OPCODE: 4 bits Operation Code
--           AA: 1 bit Authoritative Answer
--           TC: 1 bit Truncated Message
--           RD: 1 bit Recursion Desired
--           RA: 1 bit  Recursion Available
--           Z: 3 bits Reserved
--           RCODE: 4 bits Response Code

data DNSHeader = DNSHeader
  { dnsHeaderId :: !Data.Word.Word16,
    dnsHeaderFlags :: !Data.Word.Word16, -- QR OPCODE AA TC RD RA Z RCODE
    -- dnsHeaderFlagQR:: Bool,
    -- dnsHeaderFlagOPCODE:: Word4,
    -- dnsHeaderFlagAA:: Bool,
    -- dnsHeaderFlagTC:: Bool,
    -- dnsHeaderFlagRD:: Bool,
    -- dnsHeaderFlagRA:: Bool,
    -- dnsHeaderFlagZ:: Word4, -- 3 bit
    -- dnsHeaderFlagRCODE:: Word4,
    dnsHeaderNumQuestion :: !Data.Word.Word16,
    dnsHeaderNumAnswer :: !Data.Word.Word16,
    dnsHeaderNumAuthority :: !Data.Word.Word16,
    dnsHeaderNumAdditional :: !Data.Word.Word16
  }
  deriving (Show)

data DNSQuestion = DNSQuestion
  { dnsQuestionName :: !BS.ByteString,
    dnsQuestionType :: !Data.Word.Word16,
    dnsQuestionClass :: !Data.Word.Word16
  }
  deriving (Show)

data DNSRecord = DNSRecord
  { dnsRecordName :: !BS.ByteString,
    dnsRecordType :: !Data.Word.Word16,
    dnsRecordClass :: !Data.Word.Word16,
    dnsRecordTtl :: !Data.Word.Word32,
    dnsRecordData :: !BS.ByteString
  }
  deriving (Show)

data DNSPacket = DNSPacket
  { dnsPacketHeader :: !DNSHeader,
    dnsPacketQuestions :: ![DNSQuestion],
    dnsPacketAnswers :: ![DNSRecord],
    dnsPacketAuthorities :: ![DNSRecord],
    dnsPacketAdditionals :: ![DNSRecord]
  }
  deriving (Show)

-----------------------------------------------------
typeA :: Data.Word.Word16
typeA = 1

typeNs :: Data.Word.Word16
typeNs = 2

typeTxt :: Data.Word.Word16
typeTxt = 16

classIn :: Data.Word.Word16
classIn = 1
