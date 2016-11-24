module Units (tests) where

import Test.HUnit (Assertion, assertBool)
import Test.Framework (Test, testGroup)
import Test.Framework.Providers.HUnit (testCase)

import Control.Monad (replicateM_)
import Control.Monad.Trans (liftIO)

import Data.Maybe
import Data.Binary
import qualified Data.ByteString as BS

import Network.Haskoin.Crypto.Keys
import Network.Haskoin.Crypto.Ring
import Network.Haskoin.Crypto.ECDSA
import Network.Haskoin.Crypto.Hash
import Network.Haskoin.Crypto.Base58
import Network.Haskoin.Util

-- Unit tests copied from bitcoind implementation
-- https://github.com/bitcoin/bitcoin/blob/master/src/test/key_tests.cpp

strSecret1 :: String
strSecret1  = "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj"

strSecret2 :: String
strSecret2  = "5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3"

strSecret1C :: String
strSecret1C = "Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw"

strSecret2C :: String
strSecret2C = "L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g"

addr1 :: String 
addr1  = "1QFqqMUD55ZV3PJEJZtaKCsQmjLT6JkjvJ"

addr2 :: String 
addr2  = "1F5y5E5FMc5YzdJtB9hLaUe43GDxEKXENJ"

addr1C :: String
addr1C = "1NoJrossxPBKfCHuJXT4HadJrXRE9Fxiqs"

addr2C :: String
addr2C = "1CRj2HyM1CXWzHAXLQtiGLyggNT9WQqsDs"

strAddressBad :: String
strAddressBad = "1HV9Lc3sNHZxwj4Zk6fB38tEmBryq2cBiF"

sigMsg :: [String]
sigMsg = [ ("Very secret message " ++ (show (i :: Int)) ++ ": 11") 
         | i <- [0..15]
         ]

sec1 :: PrvKey
sec1  = fromJust $ fromWIF strSecret1

sec2 :: PrvKey
sec2  = fromJust $ fromWIF strSecret2

sec1C :: PrvKey
sec1C = fromJust $ fromWIF strSecret1C

sec2C :: PrvKey
sec2C = fromJust $ fromWIF strSecret2C

pub1 :: PubKey
pub1  = derivePubKey sec1

pub2 :: PubKey
pub2  = derivePubKey sec2

pub1C :: PubKey
pub1C = derivePubKey sec1C

pub2C :: PubKey
pub2C = derivePubKey sec2C

tests :: [Test]
tests =
    [ testGroup "ECDSA PRNG unit tests"
        [ testCase "signMsg produces unique sigantures" uniqueSigs
        , testCase "genPrvKey produces unique keys" uniqueKeys
        ] 
    , testGroup "bitcoind /src/test/key_tests.cpp" $
        [ testCase "Decode Valid WIF" checkPrivkey
        , testCase "Decode Invalid WIF" checkInvalidKey
        , testCase "Check private key compression" checkPrvKeyCompressed
        , testCase "Check public key compression" checkKeyCompressed
        , testCase "Check matching address" checkMatchingAddress
        ] ++ 
        ( map (\x -> (testCase ("Check sig: " ++ (show x)) 
                (checkSignatures $ doubleHash256 $ stringToBS x))) sigMsg )
    , testGroup "Trezor RFC 6979 Test Vectors"
        [ testCase "RFC 6979 Test Vector 1" (testDetSigning $ detVec !! 0)
        , testCase "RFC 6979 Test Vector 2" (testDetSigning $ detVec !! 1)
        , testCase "RFC 6979 Test Vector 3" (testDetSigning $ detVec !! 2)
        , testCase "RFC 6979 Test Vector 4" (testDetSigning $ detVec !! 3)
        , testCase "RFC 6979 Test Vector 5" (testDetSigning $ detVec !! 4)
        , testCase "RFC 6979 Test Vector 6" (testDetSigning $ detVec !! 5)
        , testCase "RFC 6979 Test Vector 7" (testDetSigning $ detVec !! 6)
        , testCase "RFC 6979 Test Vector 8" (testDetSigning $ detVec !! 7)
        , testCase "RFC 6979 Test Vector 9" (testDetSigning $ detVec !! 8)
        , testCase "RFC 6979 Test Vector 10" (testDetSigning $ detVec !! 9)
        , testCase "RFC 6979 Test Vector 11" (testDetSigning $ detVec !! 10)
        , testCase "RFC 6979 Test Vector 12" (testDetSigning $ detVec !! 11)
        ] 
    ]

{- ECDSA PRNG unit tests -}

uniqueSigs :: Assertion
uniqueSigs = do
    let msg = hash256 $ BS.pack [0..19]
        prv = fromJust $ makePrvKey 0x987654321
    ((r1,s1),(r2,s2),(r3,s3)) <- liftIO $ withSource devURandom $ do
        (Signature a b) <- signMsg msg prv
        (Signature c d) <- signMsg msg prv
        replicateM_ 20 $ signMsg msg prv
        (Signature e f) <- signMsg msg prv
        return $ ((a,b),(c,d),(e,f))
    assertBool "DiffSig" $ 
        r1 /= r2 && r1 /= r3 && r2 /= r3 &&
        s1 /= s2 && s1 /= s3 && s2 /= s3

uniqueKeys :: Assertion
uniqueKeys = do
    (k1,k2,k3) <- liftIO $ withSource devURandom $ do
        a <- genPrvKey
        b <- genPrvKey
        replicateM_ 20 genPrvKey
        c <- genPrvKey
        return (a,b,c)
    assertBool "DiffKey" $ k1 /= k2 && k1 /= k3 && k2 /= k3

{- bitcoind /src/test/key_tests.cpp -}

checkPrivkey :: Assertion
checkPrivkey = do
    assertBool "Key 1"  $ isJust $ fromWIF strSecret1
    assertBool "Key 2"  $ isJust $ fromWIF strSecret2
    assertBool "Key 1C" $ isJust $ fromWIF strSecret1C
    assertBool "Key 2C" $ isJust $ fromWIF strSecret2C

checkInvalidKey :: Assertion
checkInvalidKey = 
    assertBool "Bad key" $ isNothing $ fromWIF strAddressBad


checkPrvKeyCompressed :: Assertion
checkPrvKeyCompressed = do
    assertBool "Key 1"  $ isPrvKeyU sec1
    assertBool "Key 2"  $ isPrvKeyU sec2
    assertBool "Key 1C" $ not $ isPrvKeyU sec1C
    assertBool "Key 2C" $ not $ isPrvKeyU sec2C

checkKeyCompressed :: Assertion
checkKeyCompressed = do
    assertBool "Key 1"  $ isPubKeyU pub1
    assertBool "Key 2"  $ isPubKeyU pub2
    assertBool "Key 1C" $ not $ isPubKeyU pub1C
    assertBool "Key 2C" $ not $ isPubKeyU pub2C

checkMatchingAddress :: Assertion
checkMatchingAddress = do
    assertBool "Key 1"  $ addr1  == (addrToBase58 $ pubKeyAddr pub1)
    assertBool "Key 2"  $ addr2  == (addrToBase58 $ pubKeyAddr pub2)
    assertBool "Key 1C" $ addr1C == (addrToBase58 $ pubKeyAddr pub1C)
    assertBool "Key 2C" $ addr2C == (addrToBase58 $ pubKeyAddr pub2C)
    
checkSignatures :: Hash256 -> Assertion
checkSignatures h = do
    (sign1, sign2, sign1C, sign2C) <- liftIO $ withSource devURandom $ do
        a <- signMsg h sec1
        b <- signMsg h sec2
        c <- signMsg h sec1C
        d <- signMsg h sec2C
        return (a,b,c,d)
    assertBool "Key 1, Sign1"   $ verifySig h sign1 pub1
    assertBool "Key 1, Sign2"   $ not $ verifySig h sign2 pub1
    assertBool "Key 1, Sign1C"  $ verifySig h sign1C pub1
    assertBool "Key 1, Sign2C"  $ not $ verifySig h sign2C pub1
    assertBool "Key 2, Sign1"   $ not $ verifySig h sign1 pub2
    assertBool "Key 2, Sign2"   $ verifySig h sign2 pub2
    assertBool "Key 2, Sign1C"  $ not $ verifySig h sign1C pub2
    assertBool "Key 2, Sign2C"  $ verifySig h sign2C pub2
    assertBool "Key 1C, Sign1"  $ verifySig h sign1 pub1C
    assertBool "Key 1C, Sign2"  $ not $ verifySig h sign2 pub1C
    assertBool "Key 1C, Sign1C" $ verifySig h sign1C pub1C
    assertBool "Key 1C, Sign2C" $ not $ verifySig h sign2C pub1C
    assertBool "Key 2C, Sign1"  $ not $ verifySig h sign1 pub2C
    assertBool "Key 2C, Sign2"  $ verifySig h sign2 pub2C
    assertBool "Key 2C, Sign1C" $ not $ verifySig h sign1C pub2C
    assertBool "Key 2C, Sign2C" $ verifySig h sign2C pub2C


{- Trezor RFC 6979 Test Vectors -}
-- github.com/trezor/python-ecdsa/blob/master/ecdsa/test_pyecdsa.py

detVec :: [(Integer,String,String)]
detVec = 
    [ 
      ( 0x1
      , "Satoshi Nakamoto"
      , "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d82442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"
      )
    , ( 0x1
      , "All those moments will be lost in time, like tears in rain. Time to die..."
      , "8600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21"
      )
    , ( 0Xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
      , "Satoshi Nakamoto"
      , "fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d06b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5"
      )
    , ( 0xf8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181
      , "Alan Turing"
      , "7063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c58dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea"
      )
    , ( 0xe91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2
      , "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!"
      , "b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6"
      )
    , ( 0x0000000000000000000000000000000000000000000000000000000000000001
      , "Everything should be made as simple as possible, but not simpler."
      , "33a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c96f807982866f785d3f6418d24163ddae117b7db4d5fdf0071de069fa54342262"
      )
    , ( 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
      , "Equations are more important to me, because politics is for the present, but an equation is something for eternity."
      , "54c4a33c6423d689378f160a7ff8b61330444abb58fb470f96ea16d99d4a2fed07082304410efa6b2943111b6a4e0aaa7b7db55a07e9861d1fb3cb1f421044a5"
      )
    , ( 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
      , "Not only is the Universe stranger than we think, it is stranger than we can think."
      , "ff466a9f1b7b273e2f4c3ffe032eb2e814121ed18ef84665d0f515360dab3dd06fc95f5132e5ecfdc8e5e6e616cc77151455d46ed48f5589b7db7771a332b283"
      )
    , ( 0x0000000000000000000000000000000000000000000000000000000000000001
      , "How wonderful that we have met with a paradox. Now we have some hope of making progress."
      , "c0dafec8251f1d5010289d210232220b03202cba34ec11fec58b3e93a85b91d375afdc06b7d6322a590955bf264e7aaa155847f614d80078a90292fe205064d3"
      )
    , ( 0x69ec59eaa1f4f2e36b639716b7c30ca86d9a5375c7b38d8918bd9c0ebc80ba64
      , "Computer science is no more about computers than astronomy is about telescopes."
      , "7186363571d65e084e7f02b0b77c3ec44fb1b257dee26274c38c928986fea45d0de0b38e06807e46bda1f1e293f4f6323e854c86d58abdd00c46c16441085df6"
      )
    , ( 0x00000000000000000000000000007246174ab1e92e9149c6e446fe194d072637
      , "...if you aren't, at any given time, scandalized by code you wrote five or even three years ago, you're not learning anywhere near enough"
      , "fbfe5076a15860ba8ed00e75e9bd22e05d230f02a936b653eb55b61c99dda4870e68880ebb0050fe4312b1b1eb0899e1b82da89baa5b895f612619edf34cbd37"
      )
    , ( 0x000000000000000000000000000000000000000000056916d0f9b31dc9b637f3
      , "The question of whether computers can think is like the question of whether submarines can swim."
      , "cde1302d83f8dd835d89aef803c74a119f561fbaef3eb9129e45f30de86abbf906ce643f5049ee1f27890467b77a6a8e11ec4661cc38cd8badf90115fbd03cef"
      )
    ]

testDetSigning :: (Integer, String, String) -> Assertion
testDetSigning (prv,msg,str) = do
    assertBool "RFC 6979 Vector" $ res == (fromJust $ hexToBS str)
    assertBool "Valid sig" $ verifySig msg' sig (derivePubKey prv')
    where sig@(Signature r s) = detSignMsg msg' prv'
          msg' = hash256 $ stringToBS msg
          prv' = fromJust $ makePrvKey prv
          res = runPut' $ put (fromIntegral r :: Hash256) >> 
                          put (fromIntegral s :: Hash256)


