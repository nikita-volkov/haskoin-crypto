module Network.Haskoin.Crypto.Hash.Tests (tests) where

import Test.Framework (Test, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Network.Haskoin.Crypto.Hash
import Network.Haskoin.Crypto.Arbitrary()

tests :: [Test]
tests = 
    [ testGroup "Hash tests" 
        [ testProperty "join512( split512(h) ) == h" joinSplit512
        ]
    ]

joinSplit512 :: Hash512 -> Bool
joinSplit512 h = (join512 $ split512 h) == h

