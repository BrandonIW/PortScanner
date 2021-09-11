# We toss this in a class because that way we create a scanner object associated with a specific IP
# We want to create a socket, check a port and return whether or not it's open.

# TODO: Threading
# TODO: Write to a file
# TODO: More user-friendly list of ports and asking for the port range to scan
# TODO: Logging
# TODO: Port range validation should check and see if the first port is smaller than second port
# TODO: Regex input validation for ports & IPs
# TODO: Add banner grabbing to file/logs
# TODO: Options for presets for common ports/all ports/reserved ports etc. etc.
# TODO: Convert hostname to IP

import socket
from time import sleep
import re
import logging
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from Banner_Reading_from_Open_Ports import Grabber

# Queue is a data structure that will help us to manage the access of multiple threads on a single resource, which in
# our case will be the port numbers. Since our threads run simultaneously and scan the ports, we use queues to make sure
# that every port is only scanned once.

class Scanner:
    # IP Address Input Validation
    regex = re.compile(r'^([1-9]){1}(\d){0,2}\.(\d){1,3}\.(\d){1,3}\.(\d){1,3}$')

    # Hostname Input Validation
    regex_hostname = re.compile(r'^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$')

####### Logging ########
    # Create logger
    logger = logging.getLogger(__name__)

    # Create file handler
    info_file_handler = logging.FileHandler('loginfo.txt')

    # Add handler to logger
    logger.addHandler(info_file_handler)

    # Formatting for handler
    formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s:%(name)s')

    # Add formatting to handler
    info_file_handler.setFormatter(formatter)

    # Set log level for handler
    info_file_handler.setLevel(logging.INFO)

    # Set logger log level
    logger.setLevel(logging.DEBUG)

####### Initialization ########
    def __init__(self):
        # Input IP to Scan
        self.ip = input("Enter the IP address or hostname to scan: ")

        #If hostname, convert to IP
        if Scanner.regex_hostname.fullmatch(self.ip):
            self.ip = socket.gethostbyname('google.ca')

        # Create an empty queue. These will store our ports
        self.queue = Queue()

        # Compare with regex to ensure a match
        while not Scanner.regex.fullmatch(self.ip):
            print("Invalid IP Address. e.g. 192.168.0.4")
            self.ip = input("Enter the IP address to scan: ")

        # List of open ports that we will collect
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
                else:
                    Scanner.logger.info(f"Port: {port} is closed at IP: {self.ip}")

                sock.close()
                return result

            except OverflowError:
                print("Port must be between 0 - 65535")
                port = int(input("Input port to scan: "))

    # Adds multiple ports to queue
    def scan_range(self, lowerport, upperport):
        for port in range(int(lowerport),int(upperport)+1):
            self.queue.put(port)

    # Adds single port to queue
    def scan_port(self,port):
        self.queue.put(port)


    def worker(self):
        while not self.queue.empty():
            port = self.queue.get()

            if self.is_open(port) == 0:
                try:
                    banner = Grabber(self.ip,port).read()

                except socket.timeout:
                    banner = "N/A"

                self.open_ports.append(f"Port {port} at IP {self.ip} is open. Banner is: {banner}")

        if self.open_ports:
            self.write()
            return "Port scan completed and found one or more open ports. Results can be found in Scan_Results.txt file"

        return f"No open ports were detected at ip {self.ip}"

    # If our open_ports list has data, write it to this file
    def write(self):
        with open("Scan_Results.txt", "a") as file:
            for x in self.open_ports:
                file.write(f"{x}\n")

def main(threads=10):
    # Boolean to ask user if they want to scan another port or ports
    scanning = True

    # Port range regex for input validation
    regex = re.compile(r'^([1-6]?\d{1,4})(\W)([1-6]?\d{1,4})$')

    while scanning:

        # Select type of scan to perform
        acceptable_inputs = ['1', '2', '3', '4']
        choice = input("\n1. Scan Single Port\n2. Scan Custom Range of Ports\n3. Scan Common Ports (1-1024)\n4. Scan all ports (1-655535)\nChoose option 1-4: ")

        while choice not in acceptable_inputs:
            print("Invalid input.")
            sleep(2)
            choice = input("\n1. Scan Single Port\n2. Scan Custom Range of Ports\n3. Scan Common Ports (1-1024)\n4. Scan all ports (1-655535)\nChoose option 1-4: ")

        # Select single port to scan
        if choice == "1":
            while True:
                try:
                    port = int(input("Input port to scan: "))
                    my_scan = Scanner()
                    my_scan.scan_port(port)
                    print(my_scan.worker())
                    break

                except ValueError:
                    print("Error. Must be an integer")
                    sleep(1)



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
            my_scan.scan_range(lower,upper) # Adds to queue

            with ThreadPoolExecutor() as executor:
                for _ in range(threads):
                    executor.submit(my_scan.worker)

            if my_scan.open_ports:
                my_scan.write()
                print("Port scan completed and found one or more open ports. Results can be found in Scan_Results.txt file")
            else:
                print(f"No open ports were detected at ip {my_scan.ip}")

        if choice == "3":
            my_scan = Scanner()
            my_scan.scan_range(0,1024) # Adds to queue

            with ThreadPoolExecutor() as executor:
                for _ in range(threads):
                    executor.submit(my_scan.worker)

            if my_scan.open_ports:
                my_scan.write()
                print("Port scan completed and found one or more open ports. Results can be found in Scan_Results.txt file")
            else:
                print(f"No open ports were detected at ip {my_scan.ip}")

        if input("Do you want to scan again? (Y/N)").lower() in ["no", "n"]:
            scanning = False

        if choice == "4":
            my_scan = Scanner()
            my_scan.scan_range(0,65535) # Adds to queue

            with ThreadPoolExecutor() as executor:
                for _ in range(threads):
                    executor.submit(my_scan.worker)

            if my_scan.open_ports:
                my_scan.write()
                print("Port scan completed and found one or more open ports. Results can be found in Scan_Results.txt file")
            else:
                print(f"No open ports were detected at ip {my_scan.ip}")

        if input("Do you want to scan again? (Y/N)").lower() in ["no", "n"]:
            scanning = False

    print("You've exited the program")



if __name__ == '__main__':
    main() #Optional thread arg.