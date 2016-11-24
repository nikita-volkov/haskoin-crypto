module Network.Haskoin.Crypto.Ring.Tests (tests) where

import Test.QuickCheck.Property (Property, (==>))
import Test.Framework (Test, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Data.Bits 
    ( isSigned
    , bit
    , testBit
    , shift
    , bitSize
    , popCount
    , (.&.), (.|.)
    , xor, complement
    )
import Data.Word (Word8, Word32)
import qualified Data.ByteString as BS (length, index)

import QuickCheckUtils
import Network.Haskoin.Crypto.Arbitrary()
import Network.Haskoin.Crypto.Ring
import Network.Haskoin.Crypto.NumberTheory
import Network.Haskoin.Crypto.Curve
import Network.Haskoin.Util

tests :: [Test]
tests = 
    [ testGroup "Number Theory" 
        [ testProperty "a * inv(a) = 1 (mod p)" inverseMod
        , testProperty "a * inv(a) = 1 (mod p) in FieldP" inverseModP
        , testProperty "a * inv(a) = 1 (mod n) in FieldN" inverseModN
        , testProperty "sqrt( a^2 ) = a (mod p)" sqrtP
        ],
      testGroup "Ring Numeric"
        [ testProperty "Ring fromInteger" ringFromInteger
        , testProperty "Ring addition" ringAddition
        , testProperty "Ring multiplication" ringMult
        , testProperty "Ring negation" ringNegate
        , testProperty "Ring abs" ringAbs
        , testProperty "Ring signum" ringSignum
        ],
      testGroup "Ring Bits"
        [ testProperty "Ring AND" ringAnd
        , testProperty "Ring OR" ringOr
        , testProperty "Ring XOR" ringXor
        , testProperty "Ring Complement" ringComplement
        , testProperty "Ring Shift" ringShift
        , testProperty "Ring Bitsize" ringBitsize
        , testProperty "Ring Testbit" ringTestbit
        , testProperty "Ring Bit" ringBit
        , testProperty "Ring PopCount" ringPopCount
        , testProperty "Ring IsSigned" ringIsSigned
        ],
      testGroup "Ring Bounded"
        [ testProperty "Ring minBound" ringMinBound
        , testProperty "Ring maxBound" ringMaxBound
        ],
      testGroup "Ring Enum"
        [ testProperty "Ring succ" ringSucc
        , testProperty "Ring pred" ringPred
        , testProperty "Ring toEnum" ringToEnum
        , testProperty "Ring fromEnum" ringFromEnum
        ],
      testGroup "Ring Integral"
        [ testProperty "Ring Quot" ringQuot
        , testProperty "Ring Rem" ringRem
        , testProperty "Ring Div" ringDiv
        , testProperty "Ring Mod" ringMod
        , testProperty "Ring QuotRem" ringQuotRem
        , testProperty "Ring DivMod" ringDivMod
        , testProperty "Ring toInteger" ringToInteger
        ],
      testGroup "Ring Binary"
        [ testProperty "get( put(Hash512) ) = Hash512" getPutHash512
        , testProperty "get( put(Hash256) ) = Hash256" getPutHash256
        , testProperty "get( put(Hash160) ) = Hash160" getPutHash160
        , testProperty "get( put(FieldP) ) = FieldP" getPutModP
        , testProperty "size( put(FieldP) ) = 32" putModPSize
        , testProperty "get( put(FieldN) ) = FieldN" getPutModN
        , testProperty "Verify DER of put(FieldN)" putModNSize
        ]
    ]

{- Number Theory -}

inverseMod :: Integer -> Property
inverseMod i = p > 0 ==> (p * (mulInverse p curveP)) `mod` curveP == 1
  where 
    p = abs i

inverseModP :: FieldP -> Property
inverseModP r = r > 0 ==> r/r == 1

inverseModN :: FieldN -> Property
inverseModN r = r > 0 ==> r/r == 1

sqrtP :: FieldP -> Bool
sqrtP x = (a == x && b == (-x)) || (a == (-x) && b == x)
  where 
    (a:b:_) = quadraticResidue (x^(2 :: Int))

{- Ring Numeric -}

ringFromInteger :: Integer -> Bool
ringFromInteger i = getRingInteger ring == fromIntegral model
  where 
    model = fromInteger i :: Word32
    ring  = fromInteger i :: Test32

ringAddition :: Integer -> Integer -> Bool
ringAddition i1 i2 = getRingInteger ring == fromIntegral model
  where 
    model = (fromInteger i1) + (fromInteger i2) :: Word32
    ring  = (fromInteger i1) + (fromInteger i2) :: Test32

ringMult :: Integer -> Integer -> Bool
ringMult i1 i2 = getRingInteger ring == fromIntegral model
  where 
    model = (fromInteger i1) * (fromInteger i2) :: Word32
    ring  = (fromInteger i1) * (fromInteger i2) :: Test32

ringNegate :: Integer -> Bool
ringNegate i = getRingInteger ring == fromIntegral model
  where 
    model = negate (fromInteger i) :: Word32
    ring  = negate (fromInteger i) :: Test32

ringAbs :: Integer -> Bool
ringAbs i = getRingInteger ring == fromIntegral model
  where 
    model = abs (fromInteger i) :: Word32
    ring  = abs (fromInteger i) :: Test32

ringSignum :: Integer -> Bool
ringSignum i = getRingInteger ring == fromIntegral model
  where 
    model = signum (fromInteger i) :: Word32
    ring  = signum (fromInteger i) :: Test32

{- Ring Bits -}

ringAnd :: Integer -> Integer -> Bool
ringAnd i1 i2 = getRingInteger ring == fromIntegral model
  where 
    model = (fromInteger i1) .&. (fromInteger i2) :: Word32
    ring  = (fromInteger i1) .&. (fromInteger i2) :: Test32

ringOr :: Integer -> Integer -> Bool
ringOr i1 i2 = getRingInteger ring == fromIntegral model
  where 
    model = (fromInteger i1) .|. (fromInteger i2) :: Word32
    ring  = (fromInteger i1) .|. (fromInteger i2) :: Test32
          
ringXor :: Integer -> Integer -> Bool
ringXor i1 i2 = getRingInteger ring == fromIntegral model
  where 
    model = (fromInteger i1) `xor` (fromInteger i2) :: Word32
    ring  = (fromInteger i1) `xor` (fromInteger i2) :: Test32

ringComplement :: Integer -> Bool
ringComplement i = getRingInteger ring == fromIntegral model
  where 
    model = complement (fromInteger i) :: Word32
    ring  = complement (fromInteger i) :: Test32

ringShift :: Integer -> Word8 -> Bool
ringShift i j = getRingInteger ring == fromIntegral model
  where 
    model = shift (fromInteger i) (fromIntegral j) :: Word32
    ring  = shift (fromInteger i) (fromIntegral j) :: Test32

ringBitsize :: Integer -> Bool
ringBitsize i = ring == model
  where 
    model = bitSize ((fromInteger i) :: Word32) 
    ring  = bitSize ((fromInteger i) :: Test32) 

ringTestbit :: Integer -> Word8 -> Bool
ringTestbit i j = ring == model
  where 
    model = testBit ((fromInteger i) :: Word32) (fromIntegral j)
    ring  = testBit ((fromInteger i) :: Test32) (fromIntegral j)

ringBit :: Word8 -> Bool
ringBit i = getRingInteger ring == fromIntegral model
  where 
    model = bit (fromIntegral i) :: Word32
    ring  = bit (fromIntegral i) :: Test32

ringPopCount :: Integer -> Bool
ringPopCount i = ring == model
  where 
    model = popCount ((fromInteger i) :: Word32)
    ring  = popCount ((fromInteger i) :: Test32)

ringIsSigned :: Integer -> Bool
ringIsSigned i = ring == model
  where 
    model = isSigned ((fromInteger i) :: Word32)
    ring  = isSigned ((fromInteger i) :: Test32)

{- Ring Bounded -}

ringMinBound :: Test32 -> Bool
ringMinBound _ = (minBound :: Test32) - 1 == (maxBound :: Test32)

ringMaxBound :: Test32 -> Bool
ringMaxBound _ = (maxBound :: Test32) + 1 == (minBound :: Test32)

{- Ring Enum -}

ringSucc :: Integer -> Property
ringSucc i = (fromIntegral i) /= maxB ==> 
    getRingInteger ring == fromIntegral model
  where 
    model = succ (fromInteger i) :: Word32
    ring  = succ (fromInteger i) :: Test32
    maxB   = maxBound :: Word32

ringPred :: Integer -> Property
ringPred i = (fromIntegral i) /= minB ==> 
    getRingInteger ring == fromIntegral model
  where 
    model = pred (fromInteger i) :: Word32
    ring  = pred (fromInteger i) :: Test32
    minB   = minBound :: Word32

ringToEnum :: Word32 -> Bool
ringToEnum w = getRingInteger ring == fromIntegral model
  where 
    model = toEnum (fromIntegral w) :: Word32
    ring  = toEnum (fromIntegral w) :: Test32

ringFromEnum :: Integer -> Bool
ringFromEnum i = model == ring
  where 
    model = fromEnum ((fromInteger i) :: Word32)
    ring  = fromEnum ((fromInteger i) :: Test32)

{- Ring Integral -}

ringQuot :: Integer -> Integer -> Property
ringQuot i1 i2 = i2 /= 0 ==> getRingInteger ring == fromIntegral model
  where 
    model = (fromInteger i1) `quot` (fromInteger i2) :: Word32
    ring  = (fromInteger i1) `quot` (fromInteger i2) :: Test32

ringRem :: Integer -> Integer -> Property
ringRem i1 i2 = i2 /= 0 ==> getRingInteger ring == fromIntegral model
  where 
    model = (fromInteger i1) `rem` (fromInteger i2) :: Word32
    ring  = (fromInteger i1) `rem` (fromInteger i2) :: Test32

ringDiv :: Integer -> Integer -> Property
ringDiv i1 i2 = i2 /= 0 ==> getRingInteger ring == fromIntegral model
  where 
    model = (fromInteger i1) `div` (fromInteger i2) :: Word32
    ring  = (fromInteger i1) `div` (fromInteger i2) :: Test32

ringMod :: Integer -> Integer -> Property
ringMod i1 i2 = i2 /= 0 ==> getRingInteger ring == fromIntegral model
  where 
    model = (fromInteger i1) `mod` (fromInteger i2) :: Word32
    ring  = (fromInteger i1) `mod` (fromInteger i2) :: Test32

ringQuotRem :: Integer -> Integer -> Property
ringQuotRem i1 i2 = i2 /= 0 ==> 
    (getRingInteger r1 == fromIntegral m1) && 
    (getRingInteger r2 == fromIntegral m2)
  where 
    (m1,m2) = (fromInteger i1) `quotRem` (fromInteger i2) :: (Word32, Word32)
    (r1,r2) = (fromInteger i1) `quotRem` (fromInteger i2) :: (Test32, Test32)

ringDivMod :: Integer -> Integer -> Property
ringDivMod i1 i2 = i2 /= 0 ==> 
    (getRingInteger r1 == fromIntegral m1) && 
    (getRingInteger r2 == fromIntegral m2)
  where 
    (m1,m2) = (fromInteger i1) `divMod` (fromInteger i2) :: (Word32, Word32)
    (r1,r2) = (fromInteger i1) `divMod` (fromInteger i2) :: (Test32, Test32)

ringToInteger :: Test32 -> Bool
ringToInteger r@(Ring i) = toInteger r == i

{- Ring Binary -}

getPutHash512 :: Hash512 -> Bool
getPutHash512 r = r == (decode' $ encode' r)

getPutHash256 :: Hash256 -> Bool
getPutHash256 r = r == (decode' $ encode' r)

getPutHash160 :: Hash160 -> Bool
getPutHash160 r = r == (decode' $ encode' r)

getPutModP :: FieldP -> Bool
getPutModP r = r == (decode' $ encode' r)

putModPSize :: FieldP -> Bool
putModPSize r = BS.length (encode' r) == 32

getPutModN :: FieldN -> Property
getPutModN r = r > 0 ==> r == (decode' $ encode' r)

putModNSize :: FieldN -> Property
putModNSize r = r > 0 ==>
    (  a == 0x02    -- DER type is Integer
    && b <= 33      -- Can't be bigger than 32 + 0x00 padding
    && l == fromIntegral (b + 2) -- Advertised length matches
    && c < 0x80     -- High byte is never 1
    )
  where 
    bs = encode' r
    a  = BS.index bs 0
    b  = BS.index bs 1
    c  = BS.index bs 2
    l  = BS.length bs

