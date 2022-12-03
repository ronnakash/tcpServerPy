from Encryption import decryptWithAESPrivateKey, generateAesKey, encryptWithRSAPublicKey
from Database import Database, User, File
from Requests import CrcCheckResponsePayload, PublicKeyExchangePayload, RegistrationPayload, Request, SendFilePayload, RequestParser
from Responses import EncryptedAesKeyPayload, FileAcceptedCrcPayload, EmptyPayload, RegisterSuccessPayload, Response
from zlib import crc32 
import selectors
import socket
import time
import os

from Utils import int_to_bytes, removePadding


db = Database()

def keyExchange(request : Request) -> Response:
    requestPayload : PublicKeyExchangePayload = request.payload
    aes = generateAesKey()
    db.updateUserAesKey(requestPayload.name, aes)
    db.getUserByUsername(requestPayload.name)
    encryptedKey = encryptWithRSAPublicKey(requestPayload.public_key, aes)
    responsePayload = EncryptedAesKeyPayload(request.clientId, encryptedKey)
    return Response(2102, len(encryptedKey) + 16, responsePayload)

def registerUser(request : Request) -> Response:
    try:
        requestPayload : RegistrationPayload = request.payload
        userUuid = os.urandom(16)
        user : User = User(requestPayload.name, userUuid)
        db.saveUser(user)
        responsePayload = RegisterSuccessPayload(userUuid)
        return Response(2100, 16, responsePayload)
    except Exception as e:
        print("Error! ")
        print(e)
        return Response(2101, 0, EmptyPayload())

def saveFile(filename, fileContent):
    # make dir for user if needed
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    # write
    with open(filename, "wb") as f:
        f.write(fileContent)

    return

def getFile(request : Request) -> Response:
    requestPayload : SendFilePayload = request.payload
    userId = requestPayload.clientId
    user = db.getUserById(userId)
    filename = requestPayload.filename
    filepath2 = 'files//' + user.username + '//' + filename
    filepath = 'files/' + user.username + '/' + filename
    encryptedFile = requestPayload.messageContent
    userKey = db.getUsersAesKeyById(userId)
    # decrypt file
    fileDecryptedContent = decryptWithAESPrivateKey(userKey, encryptedFile)
    trimmed = removePadding(fileDecryptedContent)
    saveFile(filepath.rstrip('\x00'), fileDecryptedContent)
    file = File(user.uuid, filename, filepath)
    db.newFile(file)
    checksum = crc32(trimmed)
    checksumbytes = int_to_bytes(checksum)

    responsePayload = FileAcceptedCrcPayload(user.uuid, requestPayload.contentSize, filename, checksum)
    return Response(2103, 279, responsePayload)

def crcOk(request : Request) -> Response:
    return crcResponse(request, True)

def crcRetry(request : Request) -> Response:
    return Response(2104, 0, EmptyPayload())

def crcFail(request : Request) -> Response:
    return crcResponse(request, False)

def crcResponse(request : Request, boolean ) -> Response:
    requestPayload : CrcCheckResponsePayload = request.payload
    filename = requestPayload.filename
    db.updateFileVerification(filename, boolean)
    return Response(2104, 0, EmptyPayload())    


class SelectorServer:
    def __init__(self, host, port):
        # Create the main socket that accepts incoming connections and start
        # listening. The socket is nonblocking.
        self.main_socket = socket.socket()
        self.main_socket.bind((host, port))
        self.main_socket.listen(100)
        self.main_socket.setblocking(False)

        # Create the selector object that will dispatch events. Register
        # interest in read events, that include incoming connections.
        # The handler method is passed in data so we can fetch it in
        # serve_forever.
        self.selector = selectors.DefaultSelector()
        self.selector.register(fileobj=self.main_socket,
                               events=selectors.EVENT_READ,
                               data=self.on_accept)

        # Keeps track of the peers currently connected. Maps socket fd to
        # peer name.
        self.current_peers = {}

    def on_accept(self, sock, mask):
        # This is a handler for the main_socket which is now listening, so we
        # know it's ready to accept a new connection.
        conn, addr = self.main_socket.accept()
        # logging.info('accepted connection from {0}'.format(addr))
        conn.setblocking(False)

        self.current_peers[conn.fileno()] = conn.getpeername()
        # Register interest in read events on the new socket, dispatching to
        # self.on_read
        self.selector.register(fileobj=conn, events=selectors.EVENT_READ,
                               data=self.on_read)

    def close_connection(self, conn):
        # We can't ask conn for getpeername() here, because the peer may no
        # longer exist (hung up); instead we use our own mapping of socket
        # fds to peer names - our socket fd is still open.
        peername = self.current_peers[conn.fileno()]
        # logging.info('closing connection to {0}'.format(peername))
        del self.current_peers[conn.fileno()]
        self.selector.unregister(conn)
        conn.close()

    def on_read(self, conn, mask):
        # This is a handler for peer sockets - it's called when there's new
        # data.
        try:
            # peername = conn.getpeername()
            # logging.info('got data from {}'.format(peername))
            parser = RequestParser(conn)
            request = parser.parse()
            code = request.code
            response = None
            if code == 1100:
                response = registerUser(request)
            # public key exchange
            elif code == 1101:
                response = keyExchange(request)
            # send file
            elif code == 1103:
                response = getFile(request)
            # crc ok
            elif code == 1104:
                response = crcOk(request)
            # crc fail and retry
            elif code == 1105:
                response = crcRetry(request)
            # crc fail and abort
            elif code == 1106:
                response = crcFail(request)
            replydata = response.to_bytes()
            conn.send(replydata)
        except Exception as e:
            self.close_connection(conn)
        finally:
            self.close_connection(conn)


    def serve_forever(self):
        last_report_time = time.time()
        while True:
            # Wait until some registered socket becomes ready. This will block
            # for 200 ms.
            events = self.selector.select(timeout=0.2)
            # For each new event, dispatch to its handler
            for key, mask in events:
                handler = key.data
                handler(key.fileobj, mask)