import unittest
from ..packages import Encoding

class TestEncoding(unittest.TestCase):
    def testEncode(self):
        self.assertEqual(549665952565679142563431, Encoding.encodeText('teststring'), 'Encoding text string')
        self.assertNotEqual(549665952565679142563432, Encoding.encodeText('teststring'), 'last digit should be 1 instead of 2')
    
    def testDecode(self):
        self.assertEqual('teststring', Encoding.decodeBits(549665952565679142563431), 'Decoding encoded bits')