{-# LANGUAGE EmptyDataDecls #-}
module QuickCheckUtils where

import Test.QuickCheck

import Control.Applicative ((<$>))

import Network.Haskoin.Crypto.Ring
import Network.Haskoin.Crypto.Keys
import Network.Haskoin.Crypto.Curve

data Mod32
type Test32  = Ring Mod32

newtype TestPrvKeyC = TestPrvKeyC { getTestPrvKeyC :: PrvKey }
    deriving (Eq, Show)

newtype TestPrvKeyU = TestPrvKeyU { getTestPrvKeyU :: PrvKey }
    deriving (Eq, Show)

instance RingMod Mod32 where
    rFromInteger i = Ring $ i `mod` 2 ^ (32 :: Integer)
    rBitSize     _ = 32

instance Arbitrary TestPrvKeyC where
    arbitrary = do
        i <- fromInteger <$> choose (1, curveN-1)
        return $ TestPrvKeyC $ PrvKey i

instance Arbitrary TestPrvKeyU where
    arbitrary = do
        i <- fromInteger <$> choose (1, curveN-1)
        return $ TestPrvKeyU $ PrvKeyU i

