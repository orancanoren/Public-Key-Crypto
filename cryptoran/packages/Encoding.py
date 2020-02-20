import random
import hashlib
import math

# ===============================================
# Encoding functions for cryptographic algorithms
# Author: Oran Can Oren
# Email: orancanoren@gmail.com
# ===============================================

# MARK: ASCII encoding
def encodeText(messageString):
    encoded = 0
    for c in messageString:
        encoded <<= 8
        encoded += ord(c)
    return encoded

def decodeBits(encodedInt):
    decoded = ""
    encoded = int(encodedInt) # create a copy
    bitMask = 0b11111111

    while encoded != 0:
        decoded = chr(bitMask & encoded) + decoded
        encoded >>= 8
    return decoded

def divideToBlocks(messageString, blockBitLength):
    mask = 2**blockBitLength - 1
    blocks = []

    encodedInteger = encodeText(messageString)
    while encodedInteger > 0:
        currentBlock = encodedInteger & mask
        blocks.insert(0, currentBlock)
        encodedInteger >>= blockBitLength
    
    return blocks

def blocksToASCII(blocks):
    asciiString = ''
    for block in blocks:
        asciiString += decodeBits(block)
    return asciiString

# MARK: OAEP encoding
class OAEP:
    def __init__(self, blockLength = None, k0 = None, k1 = None):
        self.blockLength = blockLength
        self.k0 = k0
        self.k1 = k1

    def setOAEPparams(self, blockLength, k0, k1):
        self.blockLength = blockLength
        self.k0 = k0
        self.k1 = k1

    def generateOAEPparams(self, blockLength, k0length, k1length):
        self.k0 = random.randrange(1 << (k0length - 1), (1 << k0length - 1))
        self.k1 = random.randrange(1 << (k1length - 1), (1 << k1length) - 1)
        self.blockLength = blockLength

    def _G(self, r):
        k0len = self.k0.bit_length()
        result = 0
        salt = 0

        while result.bit_length() < (self.blockLength - k0len):
            result <<= 256
            digest = int(hashlib.sha256((r + salt).to_bytes(math.ceil(k0len / 8), 'little')).hexdigest(), 16)
            result |= digest
            salt += 1
        
        result >>= (result.bit_length() - (self.blockLength - k0len))
        return result

    def _H(self, x):
        k0len = self.k0.bit_length()
        result = 0
        salt = 0

        while result.bit_length() < k0len:
            result <<= 256
            digest = int(hashlib.sha256(str(x + salt).encode('ASCII')).hexdigest(), 16)
            result |= digest
        
        result >>= (result.bit_length() - k0len)
        return result
    
    def encode(self, messageBits):
        if self.k0 == None or self.k1 == None or self.blockLength == None:
            self.generateOAEPparams(1024, 128, 128)

        k0len = self.k0.bit_length()
        k1len = self.k1.bit_length()
        if messageBits >= (1 << (self.blockLength - k0len - k1len)):
            raise ValueError("Message too large to encode")

        # 1 - pad message with k1 zeros
        messageBits <<= k1len

        # 2 - randomly generate k0-bit string
        r = random.randrange(1 << (k0len - 1), (1 << k0len) - 1)
        
        # 3 - expand r to (n - k0len) bits and obtain x with XOR 
        x = messageBits ^ self._G(r)

        # 4 - reduce X to k0len bits and obtain y with XOR
        y = r ^ self._H(x)

        return (x << k0len) | y

    def decode(self, encodedBits):
        # Seperate X and Y
        k0len = self.k0.bit_length()
        y = encodedBits & (2**k0len - 1)
        x = encodedBits >> k0len

        # 1 - recover random string r
        r = y ^ self._H(x)

        # 2 - recover the padded message:
        paddedMessage = x ^ self._G(r)

        return paddedMessage >> self.k1.bit_length()
