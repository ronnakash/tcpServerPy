from abc import abstractmethod
from Requests import Payload, MessageBase
from Utils import int_to_bytes_with_len

RESPONSE_HEADER_SIZE = 7
CLIENT_UUID_SIZE = 16
CLIENT_NAME_SIZE = 255

class ResponsePayload(Payload):

    def __init__(self):
        pass

    @abstractmethod
    def to_bytes(self) -> bytes:
        return bytes(0)

class ResponsePayloadWithId(Payload):

    def __init__(self, clientId):
        self.clientId = clientId

    @abstractmethod
    def to_bytes(self) -> bytes:
        return bytes(0)

class Response(MessageBase):

    def __init__(self, code, payloadSize, payload: ResponsePayloadWithId):
        super().__init__(3, code, payloadSize, payload)

    def to_bytes(self):
        responseData = bytearray(RESPONSE_HEADER_SIZE + self.payloadSize)
        responseData[0] = 0x03
        codeBytes = int_to_bytes_with_len(self.code, 2)
        payload = self.payload
        payloadBytes = payload.to_bytes()
        for i in range(2):
            responseData[i+1] = codeBytes[i]
        payloadSizeBytes = int_to_bytes_with_len(self.payloadSize, 4)
        for i in range(4):
            responseData[i+3] = payloadSizeBytes[i]
        for i in range(self.payloadSize):
            responseData[i+7] = payloadBytes[i]
        return responseData

class RegisterSuccessPayload(ResponsePayloadWithId):
    def __init__(self, clientId):
        super().__init__(clientId)

    def to_bytes(self):
        cidBytes = self.clientId
        payloadBytes = bytearray(CLIENT_UUID_SIZE)
        for i in range(min(CLIENT_UUID_SIZE, len(cidBytes))):
            payloadBytes[i] = cidBytes[i]
        return payloadBytes

class EmptyPayload(Payload):
    def __init__(self):
        pass

    def to_bytes(self):
        return bytes(0)

class EncryptedAesKeyPayload(ResponsePayload):
    def __init__(self, cid, EncrtyptedKey):
        self.EncrtyptedKey = EncrtyptedKey
        self.cid = cid

    def to_bytes(self):
        cidBytes =  self.cid
        keyBytes = self.EncrtyptedKey
        payloadBytes = bytearray(16+len(keyBytes))
        for i in range(16):
            payloadBytes[i] = cidBytes[i]
        for i in range(len(keyBytes)):
            payloadBytes[i+16] = keyBytes[i]
        return payloadBytes

class FileAcceptedCrcPayload(ResponsePayloadWithId):
    def __init__(self, clientId, ContentSize, fileName, checksum):
        super().__init__(clientId)
        self.contentSize = ContentSize
        self.fileName = fileName
        self.checksum = checksum

    def to_bytes(self):
        cidBytes = self.clientId
        contentSizeBytes = int_to_bytes_with_len(self.contentSize, 4)
        fileNameBytes = bytes(self.fileName, 'ascii')
        checksumBytes = int_to_bytes_with_len(self.checksum, 4)
        payloadBytes = bytearray(279)
        for i in range(CLIENT_UUID_SIZE):
            payloadBytes[i] = cidBytes[i]
        for i in range(4):
            payloadBytes[i+CLIENT_UUID_SIZE] = contentSizeBytes[i]
        for i in range(min(CLIENT_NAME_SIZE, len(fileNameBytes))):
            payloadBytes[i+20] = fileNameBytes[i]
        for i in range(4):
            payloadBytes[i+275] = checksumBytes[i]
        return payloadBytes

