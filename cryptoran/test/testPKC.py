import unittest

from ..packages.pkc import RSA

class TestRSA(unittest.TestCase):
    def testRSAKeyGeneration(self):
        cipher = RSA()
        cipher.generateKeypair(512)

        pubkeyDict = cipher.getPubkey()
        privkeyDict = cipher.getPrivkey()

        e, n = pubkeyDict['ENCEXPONENT'], pubkeyDict['MODULUS']
        d = privkeyDict['DECEXPONENT']
        p, q = cipher.primes

        self.assertLessEqual(len(bin(n)) - 2, 512, 'modulus bit length should not exceed given parameter')
        self.assertEqual((e * d) % ((p - 1) * (q - 1)), 1, 'exponents should be inverses WRT modulo totient')       

    def testRSAEncryption(self):
        cipher = RSA()
        cipher.generateKeypair(1024)

        plaintext = 'This is a plaintext message in ASCII format!'

        c = cipher.encrypt(plaintext)
        m = cipher.decrypt(c)

        self.assertEqual(plaintext, m, 'RSA encryption/decryption routine')

    def testRSAOAEPEncryption(self):
        cipher = RSA()
        cipher.generateKeypair(1024)

        plaintext = 'This is a plaintext message in ASCII format!'

        c = cipher.encrypt(plaintext)
        m = cipher.decrypt(c)

        self.assertEqual(plaintext, m, 'RSA OAEP encryption/decryption routine')