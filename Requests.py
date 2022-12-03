from abc import ABC, ABCMeta, abstractmethod
from time import sleep

from Utils import copyBytes, int_from_bytes

class Payload(ABC):

    @abstractmethod
    def __init__(self):
        pass


class MessageBase:
    def __init__(self, version, code, payloadSize, payload : Payload):
        self.version = version
        self.code = code
        self.payloadSize = payloadSize
        self.payload = payload



class RequestPayload(Payload):
    __metaclass__= ABCMeta

    @abstractmethod
    def __init__(self):
        pass


class Request(MessageBase):

    def __init__(self, clientId, version, code, payloadSize, payload : RequestPayload):
        super().__init__(version, code, payloadSize, payload)
        self.clientId = clientId

class RegistrationPayload(RequestPayload):

    def __init__(self, name):
        self.name = name.rstrip('\x00')
    

class PublicKeyExchangePayload(RegistrationPayload):

    def __init__(self, name, PublicKey):
        super().__init__(name)
        self.public_key = PublicKey


class FileExchangePayload(RequestPayload):
    __metaclass__= ABCMeta

    @abstractmethod
    def __init__(self, clientId, filename):
        self.clientId = clientId
        self.filename = filename


class SendFilePayload(FileExchangePayload):
    def __init__(self, clientId, contentSize, filename, messageContent):
        super().__init__(clientId, filename)
        self.contentSize = contentSize
        self.messageContent = messageContent

class CrcCheckResponsePayload(FileExchangePayload):
    def __init__(self, clientId, filename):
        super().__init__(clientId, filename)


class RequestParser():
    def __init__(self, connection):
        self.connection = connection

    def recvall(self, buff, length):
        BUFF_SIZE = 65536 # 64kb
        try:
            while (length > 0):
                toReadLen = min(length, BUFF_SIZE)
                part = self.connection.recv(toReadLen)
                buff += part
                readLen = len(part)
                length -= readLen
        except Exception as e:
            sleep(0.05)
            return self.recvall(buff, length)
        return buff

    def parse(self) -> Request:
        cid  = self.connection.recv(16)
        verbits = self.connection.recv(1)
        reqCodeBits = self.connection.recv(2)
        payloadSizeBits = self.connection.recv(4)
        version = int_from_bytes(verbits)
        requestCode = int_from_bytes(reqCodeBits)
        payloadSize = int_from_bytes(payloadSizeBits)
        payloadBytes = self.recvall(b'', payloadSize)
        payload = RequestPayloadParser(payloadBytes, requestCode).parse()
        request = Request(cid, version, requestCode, payloadSize, payload)
        return request

class RequestPayloadParser():
    def __init__(self, bytes, code):
        self.message = bytes
        self.code = code
    
    def parse(self) -> RequestPayload:
        payload = None
        # registration
        if self.code == 1100:
            payload = RegistrationPayload(copyBytes(self.message, 0, 255).decode('ascii'))
        # public key exchange
        elif self.code == 1101:
            name = copyBytes(self.message, 0, 255).decode('ascii')
            key = copyBytes(self.message, 255, 160)
            payload = PublicKeyExchangePayload(name, key)
        # send file
        elif self.code == 1103:
            cid = copyBytes(self.message, 0, 16)
            contentSizeBytes = copyBytes(self.message, 16, 4)
            contentSize = int_from_bytes(contentSizeBytes)
            filename = copyBytes(self.message, 20, 255).decode('ascii')
            fileContent = copyBytes(self.message, 275, contentSize)
            payload = SendFilePayload(cid, contentSize, filename, fileContent)
        # TODO: merge all crc
        # crc ok
        elif self.code == 1104:
            cid = copyBytes(self.message, 0, 16)
            filename = copyBytes(self.message, 16, 255).decode('ascii')
            payload = CrcCheckResponsePayload(cid, filename)
        # crc fail and retry
        elif self.code == 1105:
            cid = copyBytes(self.message, 0, 16)
            filename = copyBytes(self.message, 16, 255).decode('ascii')
            payload = CrcCheckResponsePayload(cid, filename)
        # crc fail and abort
        elif self.code == 1106:
            cid = copyBytes(self.message, 0, 16)
            filename = copyBytes(self.message, 16, 255).decode('ascii')
            payload = CrcCheckResponsePayload(cid, filename)
        # TODO: handle error
        return payload
