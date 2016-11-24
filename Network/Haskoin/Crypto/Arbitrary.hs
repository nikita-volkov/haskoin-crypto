{-| 
  QuickCheck Arbitrary instances for Haskoin.Crypto types.
-}
module Network.Haskoin.Crypto.Arbitrary 
( genPrvKeyC
, genPrvKeyU
)  where

import Test.QuickCheck
import Network.Haskoin.Util.Arbitrary()

import Control.Applicative ((<$>))

import Data.Maybe

import Network.Haskoin.Crypto.Point
import Network.Haskoin.Crypto.Hash
import Network.Haskoin.Crypto.Ring
import Network.Haskoin.Crypto.ECDSA
import Network.Haskoin.Crypto.Keys
import Network.Haskoin.Crypto.Base58
import Network.Haskoin.Crypto.Curve

instance RingMod n => Arbitrary (Ring n) where
    arbitrary = fromInteger <$> arbitrary

instance Arbitrary CheckSum32 where
    arbitrary = chksum32 <$> arbitrary

instance Arbitrary Point where
    arbitrary = frequency
        [ (1, return makeInfPoint)
        , (9, (flip mulPoint $ curveG) <$> (arbitrary :: Gen FieldN))
        ]

-- | Generate an arbitrary compressed private key
genPrvKeyC :: Gen PrvKey
genPrvKeyC = do
    i <- fromInteger <$> choose (1, curveN-1)
    return $ fromJust $ makePrvKey i

-- | Generate an arbitrary uncompressed private key
genPrvKeyU :: Gen PrvKey
genPrvKeyU = do
    i <- fromInteger <$> choose (1, curveN-1)
    return $ fromJust $ makePrvKeyU i

instance Arbitrary PrvKey where
    arbitrary = oneof [genPrvKeyC, genPrvKeyU]

instance Arbitrary PubKey where
    arbitrary = derivePubKey <$> arbitrary

instance Arbitrary Address where
    arbitrary = do
        i <- fromInteger <$> choose (1,2^(160-1 :: Int))
        elements [ PubKeyAddress i
                 , ScriptAddress i
                 ]

instance Arbitrary Signature where
    arbitrary = do
        msg <- arbitrary
        prv <- prvKeyFieldN <$> arbitrary
        non <- prvKeyFieldN <$> arbitrary
        let pub  = mulPoint non curveG
        case unsafeSignMsg msg prv (non,pub) of
            (Just sig) -> return sig
            Nothing    -> arbitrary 

