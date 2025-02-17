# Import libraries
import nmap   # Allows for port scanning
import socket # Used to gather information about the system

# Function to retrieve and return the hostname and private IP address of 
# the device the script is ran from:
def get_ip():
    
    # Leverage the socket library to get information about the host:
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)

    # Return the results as a tuple (this is returned as a tuple because
    # there are multiple values separated by a comma).
    return hostname, ip_address

# Function to perform port scan by leveraging nmap:
def scan_ports(target_ip):

    # Define the ports to scan:
    ports_to_scan = list(range(1, 1025)) # Creates a list including common ports, 1-1024
    ports_to_scan.extend([3389, 8080, 8443, 3306, 5900]) # Adds additional ports

    # Convert the list of ports to scan into a str:
    port_range = ",".join(map(str, ports_to_scan))

    # To validate port range is correct, remove comment below.
    #print("The port_range str is: ", port_range)

    # Initialize the PortScanner object as "scanner":
    scanner = nmap.PortScanner()

    # Perform the scan:
    print("Scanning", target_ip, "for open ports...")
    scanner.scan(target_ip, port_range)

    # Print the results:
    for host in scanner.all_hosts():
        print("Host: ", host, scanner[host].hostname())
        print("State: ", scanner[host].state())
        
        for proto in scanner[host].all_protocols():
            print("Protocol: ", proto)
            ports = scanner[host][proto].keys()

            for port in ports:
                print("Port: ", port, " State: ", scanner[host][proto][port]["state"])

def main():

    # Gather information about device
    hostname = get_ip()

    # Scan commonly insecure ports.
    scan_ports(hostname[1])

if __name__ == "__main__":
    main()