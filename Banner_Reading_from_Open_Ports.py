import socket

class Grabber:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(5)

    def read(self, length=1024):
        try:
            self.socket.connect((self.ip, self.port))

        except socket.timeout:
            return "Socket connection timed out. Host unreachable"

        with self.socket as s:
            s.settimeout(5)
            return s.recv(length)     # Takes a set number of bytes received from the socket connection using cntx manager

def main():
    grabber = Grabber('192.168.0.63', 221)
    print(grabber.read())

if __name__ == '__main__':
    main()