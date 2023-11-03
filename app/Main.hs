-- Main.hs, final code
module Main where

import Control.Concurrent
import Network.Socket
import System.IO

type Msg = (Int, String)

runConn :: (Socket, SockAddr) -> IO ()
runConn (sock, _) = do
  hdl <- socketToHandle sock ReadWriteMode
  hSetBuffering hdl NoBuffering
  hPutStrLn hdl "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\ndhruv"
  -- hClose hdl

mainLoop :: Socket -> IO ()
mainLoop sock = do
  conn <- accept sock
  _ <- forkIO (runConn conn)
  mainLoop sock

main :: IO ()
main = do
  sock <- socket AF_INET Stream 0
  setSocketOption sock ReuseAddr 1
  bind sock (SockAddrInet 4242 0)
  listen sock 2
  mainLoop sock
