{-|
  This package provides the elliptic curve cryptography required for creating
  and validating bitcoin transactions. It also provides SHA-256 and RIPEMD-160
  hashing functions.
-}
module Network.Haskoin.Crypto
( 
  -- *Elliptic Curve Keys
  
  -- **Public Keys
  PubKey(..)
, isValidPubKey
, isPubKeyU
, derivePubKey
, pubKeyAddr
, addPubKeys

  -- **Private Keys
, PrvKey(..)
, isValidPrvKey
, makePrvKey
, makePrvKeyU
, fromPrvKey
, isPrvKeyU
, addPrvKeys
, putPrvKey
, getPrvKey
, getPrvKeyU
, fromWIF
, toWIF

  -- *ECDSA
  -- **SecretT Monad
  -- | The SecretT monad is a monadic wrapper around  HMAC DRBG (deterministic
  -- random byte generator) using SHA-256. The implementation is provided in 
  -- 'Network.Haskoin.Crypto.Hash' and the specification is defined in
  -- <http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf>. The
  -- SecretT monad is used to generate random private keys and random nonces
  -- for ECDSA signatures.
, SecretT
, withSource
, devURandom
, devRandom
, genPrvKey

  -- **Signatures
  -- | Elliptic curve cryptography standards are defined in
  -- <http://www.secg.org/download/aid-780/sec1-v2.pdf>
, Signature
, signMsg
, detSignMsg
, verifySig
, isCanonicalHalfOrder

  -- *Hash functions
, Hash512
, Hash256
, Hash160
, CheckSum32
, hash512
, hash512BS
, hash256
, hash256BS
, hash160
, hash160BS
, doubleHash256
, doubleHash256BS
, chksum32
, hmac512
, hmac512BS
, hmac256
, hmac256BS
, split512
, join512

-- *Base58 and Addresses
, Address(..)
, base58ToAddr
, addrToBase58
, encodeBase58
, decodeBase58
, encodeBase58Check
, decodeBase58Check

) where

import Network.Haskoin.Crypto.ECDSA
import Network.Haskoin.Crypto.Keys
import Network.Haskoin.Crypto.Hash
import Network.Haskoin.Crypto.Base58

