from abc import ABC, abstractmethod

class PKC:
    @abstractmethod
    def setPublicKey(self, keyDictionary):
        pass

    @abstractmethod
    def setPrivateKey(self, keyDictionary):
        pass

    @abstractmethod
    def generateKeys(self) -> tuple:
        pass

    @abstractmethod
    def encrypt(self, msg: str) -> int:
        pass

    @abstractmethod
    def decrypt(self, ciphertext: int) -> str:
        pass
    
    @abstractmethod
    def getPubkey(self) -> dict:
        pass

    @abstractmethod
    def getPrivkey(self) -> dict:
        pass