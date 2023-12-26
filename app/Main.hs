{-# LANGUAGE BinaryLiterals #-}
{-# OPTIONS_GHC -Wno-deferred-out-of-scope-variables #-}
{-# OPTIONS_GHC -Wno-missing-signatures #-}
{-# OPTIONS_GHC -Wno-name-shadowing #-}

module Main where

import Control.Monad (void,when)
import DNS
  ( DNSPacket
      ( dnsPacketAdditionals,
        dnsPacketAnswers,
        dnsPacketAuthorities
      ),
    DNSRecord (dnsRecordData, dnsRecordType),
    typeA,
    typeNs,
  )
import qualified Data.ByteString.Char8 as BS
import Data.List as L (find)
import Data.Maybe (fromMaybe)
import Data.Word (Word16)
import Debug.Trace (traceShow)
import Decode (decodeQuery)
import Encode (encodeQuery)
import Network.Socket
  ( AddrInfo (addrAddress, addrSocketType),
    Family (AF_INET),
    SocketType (Datagram),
    connect,
    defaultHints,
    defaultProtocol,
    getAddrInfo,
    socket,
  )
import Network.Socket.ByteString (recvFrom, sendTo)
import System.Environment (getArgs)
import System.Exit (exitFailure)

matchRecordType :: Word16 -> [DNSRecord] -> Maybe String
matchRecordType recordType records = do
  let matchingRecord = L.find (\x -> dnsRecordType x == recordType) records
  (\x -> Just (BS.unpack $ dnsRecordData x)) =<< matchingRecord

getAnswer :: [DNSRecord] -> Maybe String
getAnswer = matchRecordType typeA

getNsIp :: [DNSRecord] -> Maybe String
getNsIp = matchRecordType typeA

getNs :: [DNSRecord] -> Maybe String
getNs = matchRecordType typeNs

sendUDPRequest :: String -> Int -> BS.ByteString -> IO BS.ByteString
sendUDPRequest host port message = do
  sock <- socket AF_INET Datagram defaultProtocol
  let hints = defaultHints {addrSocketType = Datagram}
  addr : _ <- getAddrInfo (Just hints) (Just host) (Just $ show port)
  connect sock $ addrAddress addr
  void $ sendTo sock message (addrAddress addr)
  (result, _) <- recvFrom sock 1024
  return result

resolve :: String -> Data.Word.Word16 -> String -> IO (Maybe String)
resolve domainName recordType nameserver = do
  query <- encodeQuery domainName recordType
  byteString <- sendUDPRequest nameserver 53 query
  case decodeQuery byteString of
    Left err -> do
      traceShow ("Error parsing DNS packet: " ++ err) (return Nothing)
    Right packet -> do
      let mIp = getAnswer $ dnsPacketAnswers packet
      let mNsIp = getNsIp $ dnsPacketAdditionals packet
      let mNsDomain = getNs $ dnsPacketAuthorities packet
      case (mIp, mNsIp, mNsDomain) of
        (Just ip, _, _) -> return $ Just ip
        (_, Just nsIp, _) -> resolve domainName recordType nsIp
        (_, _, Just nsDomain) -> do
          nameserver <- resolve nsDomain typeA nameserver
          resolve domainName recordType $ fromMaybe "" nameserver
        (_, _, _) -> traceShow "Error Occured" $ return Nothing

main :: IO ()
main = do
  args <- getArgs
  let nameserver = "8.8.8.8"
  when (null args) $ 
    traceShow "Usage cabal haskell-dns-resolver <domain>" exitFailure
  let domain = head args
  ip <- resolve domain typeA nameserver
  print ip
