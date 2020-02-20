import random

# import shared modules
from .. import Encoding, Utils
from .pkc import PKC

# ==============================================
# RSA PKC implementation
# Author: Oran Can Oren
# Email: orancanoren@gmail.com
# ==============================================

class RSAPublicKey:
    def __init__(self, encryptionExponent, modulus):
        self.encryptionExponent = encryptionExponent
        self.modulus = modulus

class RSAPrivateKey:
    def __init__(self, decryptionExponent):
        self.decryptionExponent = decryptionExponent

class RSA(PKC):
    def __init__(self, enableOAEP=False, asciiEncode = True):
        # Args:
        # - pubkeyDictionary: A dictionary containing public key values
        # - privkeyDictionary: A dictionary containing private key values
        # - enableOAEP: Set true to enable OAEP encoding, type: bool
        # - oaepEncoder: OAEP encoder object used to encode/decode messages, type: Encoding.OAEP,
        # - asciiEncode: Set true to encode ASCII messages prior encryption and to decode ASCII post decryption
        self.enableOAEP = enableOAEP
        self.asciiEncode = asciiEncode
        self.publicKey = None
        self.privateKey = None

    def setPublicKey(self, keyDictionary: dict):
        dictionaryFields = keyDictionary.keys()
        if 'ENCEXPONENT' not in dictionaryFields or 'MODULUS' not in dictionaryFields:
            raise ValueError('Provided RSA public key dictionary does not contain required fields!')

        self.publicKey = RSAPublicKey(keyDictionary['ENCEXPONENT'], keyDictionary['MODULUS'])
        if self.enableOAEP:
            if ('OAEPBLOCKSIZE' not in dictionaryFields) or ('OAEPK0' not in dictionaryFields) or ('OAEPK1' not in dictionaryFields):
                raise ValueError('Provided RSA public key dictionary does not contain all/any OAEP parameters!')

            self.oaepEncoder = Encoding.OAEP(keyDictionary['OAEPBLOCKSIZE'], 
                keyDictionary['OAEPK0'], keyDictionary['OAEPK1'])

    def setPrivateKey(self, keyDictionary: dict):
        dictionaryFields = keyDictionary.keys()
        if 'DECEXPONENT' not in dictionaryFields:
            raise ValueError('Provided RSA private key dictionary does not contain the decryption exponent!')

        self.privateKey = RSAPrivateKey(keyDictionary['DECEXPONENT'])

    def generateKeypair(self, keysize, oaepBlocksize=None, oaepk0length=None, oaepk1length=None):
        '''Generates and sets the RSA keypair'''
        # Args:
        # - keysize: keysize in number of bits to generate
        # - oaepBlocksize: blocksize parameter of OAEP
        # - oaepk0length: length of k0 in bits
        # - oaepk1length: length of k1 in bits
        # If any of the OAEP parameters are provided, all of the OAEP parameters are expected.
        # if not given and OAEP is enabled, default OAEP parameters (1024, 128, 128) is used

        # 1 - check the parameters
        if any([oaepBlocksize, oaepk0length, oaepk1length]) and not all([oaepBlocksize, oaepk0length, oaepk1length]):
            raise Exception("Insufficient OAEP parameters are provided")
        
        if 0 > keysize or keysize > 8192:
            raise Exception("Key size is not in range (0, 8192]")

        # 2 - set OAEP parameters if enabled
        if self.enableOAEP:
            self.oaepEncoder.generateOAEPparams(oaepBlocksize, oaepk0length, oaepk1length)
        
        # 3 - pick primes
        p = Utils.randomLargePrime(keysize // 2)
        q = Utils.randomLargePrime(keysize // 2)
        while p == q:
            q = Utils.randomLargePrime(keysize // 2)

        # 4 - compute the modulus
        n = p * q

        # 5 - pick encryption exponent
        totient = (p - 1) * (q - 1)
        e = 2
        while Utils.EEA(e, totient)[0] != 1:
            e = random.randint(2, totient - 1)

        # 6 - compute decryption exponent
        d = Utils.multiplicative_inverse(e, totient)

        self.primes = (p, q)
        self.publicKey = RSAPublicKey(e, n, )
        self.privateKey = RSAPrivateKey(d)

    def encrypt(self, messageString) -> int:
        if not self.publicKey:
            raise ValueError('Public key not set at time of encryption!')

        if self.asciiEncode:
            messageString = Encoding.encodeText(messageString)
            
        if self.enableOAEP:
            messageString = self.oaepEncoder.encode(messageString)
        return pow(messageString, self.publicKey.encryptionExponent, self.publicKey.modulus)

    def decrypt(self, ciphertext) -> str:
        if not self.privateKey:
            raise Exception("Private key not set at time of decryption!")
        decrypted = pow(ciphertext, self.privateKey.decryptionExponent, self.publicKey.modulus)
        if self.enableOAEP:
            decrypted = self.oaepEncoder.decode(decrypted)
        if self.asciiEncode:
            decrypted = Encoding.decodeBits(decrypted)
        return decrypted

    def getPrivkey(self) -> dict:
        keyDictionary = {
            'DECEXPONENT': self.privateKey.decryptionExponent,
        }

        return keyDictionary


    def getPubkey(self) -> dict:
        keyDictionary = {
            'ENCEXPONENT': self.publicKey.encryptionExponent,
            'MODULUS': self.publicKey.modulus
        }

        if self.enableOAEP:
            keyDictionary['OAEPBLOCKSIZE'] = self.oaepEncoder.blockLength
            keyDictionary['OAEPK0'] = self.oaepEncoder.k0
            keyDictionary['OAEPK1'] = self.oaepEncoder.k1

        return keyDictionary