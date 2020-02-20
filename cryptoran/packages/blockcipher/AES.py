import os, sys
from functools import reduce
from .Mode import Mode
from .BlockCipher import BlockCipher

# import shared modules
from .. import Encoding, Utils

# =================================================
# Advanced Encryption Standard (AES) Implementation 
# Implemented for 128 bit keys
# Author: Oran Can Oren
# Email: orancanoren@gmail.com
# =================================================
 
# MARK: class AESlayer begins
class AESlayer:
    @staticmethod
    def addRoundKey(stateArray, key):
        for i in range(16):
            currentKeyByte = key & 0b11111111
            key >>= 8
            stateArray[15 - i] ^= currentKeyByte
        return stateArray

    @staticmethod
    def substituteBytes(stateArray, inverse = False):
        S = [ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 
        0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 
        0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 
        0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 
        0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 
        0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 
        0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 
        0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 
        0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 
        0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 
        0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 
        0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 
        0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 
        0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 
        0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 
        0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 
        0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 
        0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 
        0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 
        0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 
        0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 
        0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 
        0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 
        0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 
        0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 
        0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 ]

        Si =[ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 
        0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 
        0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 
        0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 
        0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 
        0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 
        0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 
        0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 
        0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 
        0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 
        0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 
        0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 
        0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 
        0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 
        0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 
        0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 
        0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 
        0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 
        0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 
        0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 
        0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 
        0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 
        0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 
        0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 
        0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 
        0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]

        #print("sarray", stateArray)
        if inverse:
            stateArray = [Si[x] for x in stateArray]
        else:
            stateArray = [S[x] for x in stateArray]

        return stateArray

    @staticmethod
    def shiftRows(stateArray, inverse = False):
        if not inverse:
            # shift 2nd row to left by 1
            stateArray[1], stateArray[5], stateArray[9], stateArray[13] = \
            stateArray[5], stateArray[9], stateArray[13], stateArray[1]

            # shift 3rd row to left by 2
            stateArray[2], stateArray[6], stateArray[10], stateArray[14] = \
            stateArray[10], stateArray[14], stateArray[2], stateArray[6]

            # shift 4th row to left by 3
            stateArray[3], stateArray[7], stateArray[11], stateArray[15] = \
            stateArray[15], stateArray[3], stateArray[7], stateArray[11]
        
        else:
            # shift 2nd row to right by 1
            stateArray[5], stateArray[9], stateArray[13], stateArray[1] = \
            stateArray[1], stateArray[5], stateArray[9], stateArray[13]

            # shift 3rd row to right by 2
            stateArray[10], stateArray[14], stateArray[2], stateArray[6] = \
            stateArray[2], stateArray[6], stateArray[10], stateArray[14]

            # shift 4th row to right by 3
            stateArray[15], stateArray[3], stateArray[7], stateArray[11] = \
            stateArray[3], stateArray[7], stateArray[11], stateArray[15]

        return stateArray

    @staticmethod
    def mixColumns(stateArray, inverse = False):
        transformationMatrix = [[2, 3, 1, 1],
                                [1, 2, 3, 1],
                                [1, 1, 2, 3],
                                [3, 1, 1, 2]]

        invTransformationMatrix = [[0xE, 0xB, 0xD, 0x9],
                                   [0x9, 0xE, 0xB, 0xD],
                                   [0xD, 0x9, 0xE, 0xB],
                                   [0xB, 0xD, 0x9, 0xE]]

        def galoisMult(a, b):
            p = 0
            hiBitSet = 0
            for _ in range(8):
                if b & 1 == 1:
                    p ^= a
                hiBitSet = a & 0x80
                a <<= 1
                if hiBitSet == 0x80:
                    a ^= 0x1b
                b >>= 1
            return p % 256

        dotMultiplicationResult = [0]*16
        matrix = invTransformationMatrix if inverse else transformationMatrix
        for i, row in enumerate(matrix):
            for j in range(4):
                currentByte = 0
                for k in range(4):
                    currentByte ^= galoisMult(row[k], stateArray[4*j + k])
                dotMultiplicationResult[4*j + i] = currentByte
        return dotMultiplicationResult
    # MARK: class AESlayer ends

class AES(BlockCipher):
    def __init__(self, mode, key = None, IV = None):
        super().__init__(128)
        self.key = key
        if self.key == None:
            self.key = self.generateRandomKey()
        self.roundKeys = [0]
        self.mode = Mode(self, mode, IV)
        
    def _generateRoundKeys(self):
        key = int(self.key)

        # 1 - obtain the initial column of 4-bytes (1 word)
        keyMatrix = []
        for _ in range(4): # key is 128 bits long
            keyMatrix.insert(0, key & (2**32 - 1))
            key >>= 32

        # 2 - obtain the remaining 40 columns
        for roundNum in range(1, 11):
            # 2.1 - obtain W_(i - 1) and its bytes seperately
            prevWord = keyMatrix[(roundNum * 4) - 1]

            bytesOfWord = []
            for _ in range(4):
                bytesOfWord.insert(0, prevWord & 0b11111111)
                prevWord >>= 8
            
            # 2.2 - left shift W_(i - 1) bytes by one
            bytesOfWord[0], bytesOfWord[1], bytesOfWord[2], bytesOfWord[3] = \
            bytesOfWord[1], bytesOfWord[2], bytesOfWord[3], bytesOfWord[0]

            # 2.3 - substitute bytes
            substituted = AESlayer.substituteBytes(bytesOfWord)

            # 2.4 - compute the round constant
            rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
            currentRcon = rcon[roundNum]

            # 2.5 - compute T(W_(i - 1)) and get W_i
            substituted[0] ^=  currentRcon
            firstWordOfRound = 0
            for i in range(4):
                firstWordOfRound <<= 8
                firstWordOfRound ^= substituted[i]

            firstWordOfRound ^= keyMatrix[(roundNum - 1) * 4]

            keyMatrix.append(firstWordOfRound)

            # 2.6 - W_4k is obtained, remaining 3 words can be derived by simple XOR

            for i in range(3):
                currentIndex = (roundNum * 4) + i + 1
                keyMatrix.append(keyMatrix[currentIndex - 1] ^ keyMatrix[currentIndex - 4])

        self.roundKeys = []
        for i in range(11):
            roundKey = 0
            for j in range(4):
                roundKey <<= 32
                roundKey |= keyMatrix[i*4 + j]
            self.roundKeys.append(roundKey)

    def getKeys(self) -> dict:
        keyDict = { 'AES_KEY': self.key }
        if self.mode._iv:
            keyDict['AES_IV'] = self.mode._iv
        return keyDict

    def encryptBlock(self, block):
        if self.roundKeys[0] == 0:
            self._generateRoundKeys()
        
        # seperate bytes of the block to obtain the state array
        encryptedBlock = [] # state array
        while block > 0:
            byte = block & 0b11111111
            block >>= 8
            encryptedBlock.insert(0, byte)

        # pad block with leading 0's if necessary
        while len(encryptedBlock) < 16:
            encryptedBlock.append(0)

        # perform a key addition layer before iterative rounds
        encryptedBlock = AESlayer.addRoundKey(encryptedBlock, self.roundKeys[0])
        # first 9 rounds consist of 4 layers
        for roundNum in range(9):
            # 1 - byte substitution
            encryptedBlock = AESlayer.substituteBytes(encryptedBlock)

            # 2 - shift row
            encryptedBlock = AESlayer.shiftRows(encryptedBlock)

            # 3 - mix column
            encryptedBlock = AESlayer.mixColumns(encryptedBlock)

            # 4 - key addition
            encryptedBlock = AESlayer.addRoundKey(encryptedBlock, self.roundKeys[roundNum + 1])

        # last round doesn't have the mix column layer
        encryptedBlock = AESlayer.substituteBytes(encryptedBlock)
        encryptedBlock = AESlayer.shiftRows(encryptedBlock)
        encryptedBlock = AESlayer.addRoundKey(encryptedBlock, self.roundKeys[10])

        # put together the bytes in <encryptedBlock>
        encryptedBlockInt = 0
        for byte in encryptedBlock:
            encryptedBlockInt <<= 8
            encryptedBlockInt |= byte
        return encryptedBlockInt

    def decryptBlock(self, block):
        if self.roundKeys[0] == 0:
            self._generateRoundKeys()

        decryptedBlock = [] # state array

        while block > 0:
            byte = block & 0b11111111
            block >>= 8
            decryptedBlock.insert(0, byte)

        # 1 - Reverse the final round of encryption
        decryptedBlock = AESlayer.addRoundKey(decryptedBlock, self.roundKeys[10])
        decryptedBlock = AESlayer.shiftRows(decryptedBlock, True)
        decryptedBlock = AESlayer.substituteBytes(decryptedBlock, True)

        # 2 - Reverse 9 following rounds
        for roundNum in range(9):
            # 1 - key addition
            decryptedBlock = AESlayer.addRoundKey(decryptedBlock, self.roundKeys[9 - roundNum])

            # 2 - inverse mix column
            decryptedBlock = AESlayer.mixColumns(decryptedBlock, True)

            # 3 - inverse shift rows
            decryptedBlock = AESlayer.shiftRows(decryptedBlock, True)

            # 4 - inverse byte substitution
            decryptedBlock = AESlayer.substituteBytes(decryptedBlock, True)

        # 3 - Reverse the initial key addition layer of encryption
        decryptedBlock = AESlayer.addRoundKey(decryptedBlock, self.roundKeys[0])

        # put together the bytes in <decryptedBlock>
        decryptedBlockInt = 0
        for byte in decryptedBlock:
            # if a byte consists of all 0's, this means that the block was padded with a 0-byte,
            # the block has been finished!
            if byte == 0:
                break
            decryptedBlockInt <<= 8
            decryptedBlockInt |= byte
        return decryptedBlockInt

    def encrypt(self, messageString):
        blocks = Encoding.divideToBlocks(messageString, 128) # blocks of 128 bits
        encryptedBlocks = self.mode.encrypt(blocks)
        return encryptedBlocks

    def decrypt(self, blocks):
        decryptedBlocks = self.mode.decrypt(blocks)
        return Encoding.blocksToASCII(decryptedBlocks)

if __name__ == "__main__":
    print("AES-128 Encryption tool")

    # Get the mode of operation
    mode = input("Enter the mode of operation (CBC, ECB):\n>> ")
    iv = None
    if mode == 'CBC':
        iv = input('Enter the initial vector for CBC mode (leave blank for random)\n>> ')
        if iv == '':
            iv = Utils.randomNumber(128)
            print('IV:', hex(iv))

   # Get the key 
    AESkey = input("Enter the 128-bit AES key in hex (leave blank for random key generation):\n>> ")
    if AESkey == "":
        AESkey = Utils.randomNumber(128)
        print("AES key:", hex(AESkey))
    else:
        AESkey = int(AESkey, 16)

    # Instantiate the AES class
    crypt = AES(AESkey, mode, iv)

    messageString = input("Enter text\n>> ")
    encryptedBlocks = crypt.encrypt(messageString)
    for i, block in enumerate(encryptedBlocks):
        print(f"encrypted block {i}: {hex(block)}")

    decryptionResult = crypt.decrypt(encryptedBlocks)
    print("Decryption result:\n" + decryptionResult)