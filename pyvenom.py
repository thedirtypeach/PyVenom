'''
        A simple Python vulnerability scanner. This is a proof-of-concept tool built
    with the intention of building familiarity with Python, Nmap, and eventually
    retrieving a list of software and versions from a Windows machine and comparing those
    with a known-malicious software.

        The tool is currently in a pre-mvp state.

        TODO Build out a readme.md for the github repository
'''

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

# Function to perform port scan of commonly used ports.
# - Depends on 'nmap' library
# - Requires an ip address as an argument
# - Returns nothing and instead prints text to host.
# -
# - TODO Returns a list of dictionaries as json formatted text
def scan_ports(target_ip):

    # Define the ports to scan:
    ports_to_scan = list(range(1, 1025)) # Creates a list for a range of numbers
    ports_to_scan.extend([3389, 8080, 8443, 3306, 5900]) # Adds additional numbers to list

    # Convert the list of ports to scan into a string:
    port_range = ",".join(map(str, ports_to_scan))

    # To validate port range is correct, remove comment below.
    #print("The port_range str is: ", port_range)

    # Initialize the PortScanner object as "scanner":
    scanner = nmap.PortScanner()

    # Perform the scan:
    print("Scanning", target_ip, "for open ports...")
    scanner.scan(target_ip, port_range) # Calls the scan function from the PortScanner class

    # Print the results:
    for host in scanner.all_hosts(): # For each host, do the following
        print("Host: ", host, scanner[host].hostname())
        print("State: ", scanner[host].state())
        
        for proto in scanner[host].all_protocols(): # For each protocol, for each host,
            print("Protocol: ", proto)              # do the following:
            ports = scanner[host][proto].keys()

            for port in ports:
                print("Port: ", port, " State: ", scanner[host][proto][port]["state"])

# The main function
# Retrieves information about the device and calls the 'scan_ports' function to determine
# and common port misconfigurations/vulnerabilities.
def main():

    # Gather information about device
    hostname = get_ip()

    # Scan commonly insecure ports.
    scan_ports(hostname[1])

    # TODO Suggest remediation action TODO
    #remediation_steps()

# Run the main funtion
if __name__ == "__main__":
    main()