module Main where

import Test.Framework (defaultMain)

-- Property testing
import qualified Network.Haskoin.Crypto.Ring.Tests (tests)
import qualified Network.Haskoin.Crypto.Point.Tests (tests)
import qualified Network.Haskoin.Crypto.ECDSA.Tests (tests)
import qualified Network.Haskoin.Crypto.Base58.Tests (tests)
import qualified Network.Haskoin.Crypto.Keys.Tests (tests)
import qualified Network.Haskoin.Crypto.Hash.Tests (tests)

-- Unit testing
import qualified Units (tests)
import qualified Network.Haskoin.Crypto.Hash.Units (tests)

main :: IO ()
main = defaultMain
    (  Network.Haskoin.Crypto.Ring.Tests.tests 
    ++ Network.Haskoin.Crypto.Point.Tests.tests 
    ++ Network.Haskoin.Crypto.ECDSA.Tests.tests 
    ++ Network.Haskoin.Crypto.Base58.Tests.tests 
    ++ Network.Haskoin.Crypto.Hash.Tests.tests 
    ++ Network.Haskoin.Crypto.Hash.Units.tests
    ++ Network.Haskoin.Crypto.Keys.Tests.tests 
    ++ Units.tests
    )

