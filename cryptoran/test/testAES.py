import unittest

from ..packages.blockcipher import AES

class TestAES(unittest.TestCase):
    def testECBEncryption(self): # more of an integration test rather than a unit test
        cipher = AES('ecb', 0xB054A58D4D929D2F58E82110D50BB9B2)
        self.assertEqual([0xA381B27A67CB81C6F56B8AF52C3DA951], cipher.encrypt('s0me sTrinG!'))

    def testCBCshort(self):
        cipher = AES('cbc', 0xFC8CB94510FA8F9A1E9C4204115E2CD8, 0xA4501BBEE9D9D0899F2F326E0E90A968)
        self.assertEqual([0xE250CAC5745C45364F4B02F4AD8C1EA1], cipher.encrypt('some string'))

    def testCBCtwoBlock(self):
        cipher = AES('cbc', 0xFC8CB94510FA8F9A1E9C4204115E2CD8, 0xA4501BBEE9D9D0899F2F326E0E90A968)
        self.assertEqual([
            0xFF6D583741C427DCB31F020B20FD158D,
            0xB26396E8901DFDA6B0B5531D4E59BA96
        ], cipher.encrypt('some string that is long'))