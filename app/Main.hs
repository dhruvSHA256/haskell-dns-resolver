{-# LANGUAGE BinaryLiterals #-}
{-# OPTIONS_GHC -Wno-deferred-out-of-scope-variables #-}
{-# OPTIONS_GHC -Wno-missing-signatures #-}
{-# OPTIONS_GHC -Wno-name-shadowing #-}

module Main where

import Control.Monad (void)
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
import Data.Maybe (fromMaybe, isJust)
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

getAnswer :: [DNSRecord] -> Maybe String
getAnswer records = do
  let matchingRecord = L.find (\x -> dnsRecordType x == typeA) records
  case matchingRecord of
    Just x -> Just (BS.unpack $ dnsRecordData x)
    Nothing -> Nothing

getNsIp :: [DNSRecord] -> Maybe String
getNsIp records = do
  let matchingRecord = L.find (\x -> dnsRecordType x == typeA) records
  case matchingRecord of
    Just x -> Just (BS.unpack $ dnsRecordData x)
    Nothing -> Nothing

getNs :: [DNSRecord] -> Maybe String
getNs records = do
  let matchingRecord = L.find (\x -> dnsRecordType x == typeNs) records
  case matchingRecord of
    Just x -> Just (BS.unpack $ dnsRecordData x)
    Nothing -> Nothing

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
      let ip = getAnswer $ dnsPacketAnswers packet
      let nsIp = getNsIp $ dnsPacketAdditionals packet
      let nsDomain = getNs $ dnsPacketAuthorities packet
      if isJust ip
        then case ip of
          Just xx -> return (Just xx)
          Nothing -> traceShow "Error Occured (ip)" $ return Nothing
        else
          if isJust nsIp
            then case nsIp of
              Just nsIP -> resolve domainName recordType nsIP
              Nothing -> traceShow "Error Occured (nsIp)" $ return Nothing
            else do
              case nsDomain of
                Just d -> do
                  nameserver <- resolve d typeA nameserver
                  resolve domainName recordType $ fromMaybe "" nameserver
                Nothing -> traceShow "Error Occured (nsDomain)" $ return Nothing

main :: IO ()
main = do
  args <- getArgs
  let nameserver = "8.8.8.8"
  let domain = head args
  ip <- resolve domain typeA nameserver
  print ip
