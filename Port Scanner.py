# We toss this in a class because that way we create a scanner object associated with a specific IP
# We want to create a socket, check a port and return whether or not it's open, basically. With this, we can create and store
# all ports in this object which we can then call later to do what we want with.

# TODO: Threading
# TODO: Write to a file
# TODO: More user-friendly list of ports and asking for the port range to scan
# TODO: Logging
# TODO: Port range validation should check and see if the first port is smaller than second port
# TODO: Regex input validation for ports & IPs


import socket
from Timer_Decorator import timefunc
from time import sleep
import re
import logging
from concurrent.futures import ThreadPoolExecutor
from queue import Queue

# Queue is a data structure that will help us to manage the access of multiple threads on a single resource, which in
# our case will be the port numbers. Since our threads run simultaneously and scan the ports, we use queues to make sure
# that every port is only scanned once.

class Scanner:
    # IP Address Input Validation
    regex = re.compile(r'^([1-9]){1}(\d){0,2}\.(\d){1,3}\.(\d){1,3}\.(\d){1,3}$')

    # Logging Setup
    logger = logging.getLogger(__name__)                                              # Create logger
    info_file_handler = logging.FileHandler('loginfo.txt')                            # Create file handler
    logger.addHandler(info_file_handler)                                              # Add handler to logger
    formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s:%(name)s')   # Formatting for handler
    info_file_handler.setFormatter(formatter)                                         # Add formatting to handler
    info_file_handler.setLevel(logging.INFO)                                          # Set log level for handler
    logger.setLevel(logging.DEBUG)                                                    # Set logger log level

    def __init__(self):
        self.ip = input("Enter the IP address to scan: ")
        self.queue = Queue()                                                          # Currently our queue is empty
        while not Scanner.regex.fullmatch(self.ip):
            print("Invalid IP Address. e.g. 192.168.0.4")
            self.ip = input("Enter the IP address to scan: ")

        self.open_ports = []

    def __repr__(self):
        return f"Scanner IP: {self.ip}"


    def is_open(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)         # Create a socket connection
        sock.settimeout(2)                                               # Set socket timeout


        while True:
            try:
                print(f"Scanning port {port} on IP {self.ip}")
                result = sock.connect_ex((self.ip,port))                 # Returns 0 if successful socket connection

                if result == 0:
                    Scanner.logger.info(f"Port: {port} is open at IP: {self.ip}")
                Scanner.logger.info(f"Port: {port} is closed at IP: {self.ip}")

                sock.close()
                return result

            except OverflowError:
                print("Port must be between 0 - 65535")
                port = int(input("Input port to scan: "))

    # Adds port(s) to queue
    def scan_range(self, lowerport, upperport):
        for port in range(int(lowerport),int(upperport)+1):
            self.queue.put(port)


    def scan_port(self,port):
        self.queue.put(port)


    def worker(self):
        while not self.queue.empty():
            port = self.queue.get()
            self.open_ports.append(f"Port {port} at IP {self.ip} is open") if self.is_open(port) == 0 else None

        if self.open_ports:
            self.write()
            print("Port scan completed and found one or more open ports. Results can be found in Scan_Results.txt file")
        print(f"No open ports were detected at ip {self.ip}")

    def write(self):
        with open("Scan_Results.txt", "a") as file:
            for x in self.open_ports:
                file.write(f"{x}\n")

def main(threads=5):
    scanning = True

    # Port range validation. 2nd capturing group is for the delimiter
    # regex_5digits_starts_6 = re.compile(r'^(6[0-5]\d{3})(\W)(6[0-5]\d{3})$')
    # regex_5digits = re.compile(r'^(\d{5})(\W)(\d{5})$')
    regex = re.compile(r'^([1-6]?\d{1,4})(\W)([1-6]?\d{1,4})$')

    while scanning:
        acceptable_inputs = ['1', '2']
        choice = input("Do you want to scan a single port, or a range?\n1. Single Port\n2. Range of Ports\nPlease Choose 1 or 2: ")

        while choice not in acceptable_inputs:
            print("Invalid input.")
            sleep(2)
            choice = input("Do you want to scan a single port, or a range?\n1. Single Port\n2. Range of Ports\nPlease Choose 1 or 2: ")

        # Select single port to scan
        if choice == "1":
            port = int(input("Input port to scan: "))
            my_scan = Scanner()
            my_scan.scan_port(port)
            my_scan.worker()

        # Select range of ports. We unpack from the regex.search method to separate delimiter
        if choice == "2":
            port_range = input("Input port range. e.g. 22-34: ")

            # Check for full match
            while not regex.fullmatch(port_range):
                port_range = input("Invalid input. Try again. e.g. 22-34: ")

            # If match, separate based on groups and run
            lower,upper = regex.search(port_range).group(1,3)

            while (int(lower) > int(upper)):
                port_range = input("Port range must be in ascending order. Input port range e.g. 22-34: ")
                lower,upper = regex.search(port_range).group(1,3)

            my_scan = Scanner()
            my_scan.scan_range(lower,upper)

            with ThreadPoolExecutor() as executor:
                for _ in range(threads):
                    executor.submit(my_scan.worker)

            if my_scan.open_ports:
                my_scan.write()
                print("Port scan completed and found one or more open ports. Results can be found in Scan_Results.txt file")
            print(f"No open ports were detected at ip {my_scan.ip}")


        if input("Do you want to scan again? (Y/N)").lower() in ["no", "n"]:
            scanning = False

    print("You've exited the program")



if __name__ == '__main__':
    main() #Optional thread arg.