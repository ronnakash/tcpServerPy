from SelectorServer import SelectorServer

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65450 # Port to listen on 
        
if __name__ == '__main__':
    server = SelectorServer(host=HOST, port=PORT)
    server.serve_forever()

