from abc import ABC, abstractmethod
from .. import Utils

class BlockCipher(ABC):
    def __init__(self, keylength):
        self.keylength = keylength
        super().__init__()

    @abstractmethod
    def encryptBlock(self, block: int) -> int:
        pass
    
    @abstractmethod
    def decryptBlock(self, block: int) -> int:
        pass

    @abstractmethod
    def encrypt(self, messageString: str):
        pass

    @abstractmethod
    def decrypt(self, blocks: list) -> str:
        pass

    def generateRandomKey(self) -> int:
        return Utils.randomNumber(self.keylength)