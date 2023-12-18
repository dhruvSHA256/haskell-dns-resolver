module Decode where

import Control.Monad (replicateM)
import DNS
  ( DNSHeader
      ( DNSHeader,
        dnsHeaderNumAdditional,
        dnsHeaderNumAnswer,
        dnsHeaderNumAuthority,
        dnsHeaderNumQuestion
      ),
    DNSPacket (DNSPacket),
    DNSQuestion (DNSQuestion),
    DNSRecord (..),
    typeA,
    typeNs,
  )
import Data.Binary.Get
  ( Get,
    getByteString,
    getInt16be,
    getInt8,
    getWord16be,
    getWord32be,
    runGetOrFail,
  )
import Data.Bits (Bits (testBit, (.&.)))
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy as LBS
import Data.List as L (intercalate)
import Data.Word (Word16, Word8)
import Debug.Trace (traceShow)

getDNSHeader :: Get DNSHeader
getDNSHeader = DNSHeader <$> getWord16be <*> getWord16be <*> getWord16be <*> getWord16be <*> getWord16be <*> getWord16be

getDomainName :: BS.ByteString -> Get BS.ByteString
getDomainName input' = do
  len <- getInt8
  let lengthValue = len Data.Bits..&. 63
  getDomainName' input' len lengthValue
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
    isPointer c = Data.Bits.testBit c 7 && Data.Bits.testBit c 6

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
    getRecordData :: Data.Word.Word16 -> Int -> Get BS.ByteString
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

decodeQuery :: BS.ByteString -> Either String DNSPacket
decodeQuery bs =
  case runGetOrFail (getDNSPacket bs) (LBS.fromStrict bs) of
    Left (_, _, err) -> Left err
    Right (_, _, dnsPacket) -> Right dnsPacket
