import random
from .. import Encoding, Utils

# ==============================================
# El Gamal PKC implementation
# Author: Oran Can Oren
# Email: orancanoren@gmail.com
# ==============================================

class ElGamal:
    def __init__(self):
        self.publicKey = None
        self.privateKey = None
        self.p = None
        self.g = None
    
    def generateKeypair(self):
        # 1 - compute p & q
        p, g = Utils.getGroupWithGenerator(256)

        # 3 - compute private and public keys
        b = random.randint(2, p)
        B = pow(g, b, p)

        self.publicKey = B
        self.privateKey = b
        self.p = p
        self.g = g

    def _checkKeyDictionary(dictionary: dict, requiredFields):
        # requiredFields is expected to be an iterable, where each element is a
        # required key in dictionary
        keys = dictionary.keys()

        for field in requiredFields:
            if not field in keys:
                return False
        return True

    def encrypt(self, messageString):
        encodedMessage = Encoding.encodeText(messageString)
        if encodedMessage >= self.p:
            raise Exception("Message too large, cannot encrypt!")

        secret = random.randint(2, self.p - 1)
        r = pow(self.g, secret, self.p)
        t = pow(self.publicKey, secret, self.p) * encodedMessage % self.p
        return (r, t)

    def decrypt(self, r, t):
        r_inv = Utils.multiplicative_inverse(r, self.p)
        r_inv_b = pow(r_inv, self.privateKey, self.p)
        decrypted = (r_inv_b * t) % self.p
        return Encoding.decodeBits(decrypted)