# Attack-on-Windows-machine-blue
MS17-010 is a security vulnerability in Microsoft's implementation of the SMB (Server Message Block) protocol. SMB is a network file sharing protocol that allows applications to read and write to files and request services from server programs in a network. This vulnerability was discovered by the NSA (National Security Agency) and leaked by a group called The Shadow Brokers in April 2017.

The MS17-010 vulnerability affects multiple versions of Microsoft Windows operating systems, including Windows Vista, Windows 7, Windows 8.1, Windows 10, Windows Server 2008, Windows Server 2012, and Windows Server 2016. It allows an attacker to execute arbitrary code on the target system, potentially taking control of the system, by sending specially crafted packets to the SMB server.

Exploiting this vulnerability typically involves sending a crafted packet to the SMB server, causing a buffer overflow or other memory corruption, which can then be leveraged to execute malicious code. Once exploited, an attacker could install malware, steal data, or perform other malicious actions on the compromised system.

The MS17-010 exploit became infamous due to its involvement in the WannaCry ransomware attack that occurred in May 2017. WannaCry leveraged this vulnerability to spread rapidly across networks, encrypting files on infected systems and demanding ransom payments in exchange for decryption keys.

Microsoft released security patches to address the MS17-010 vulnerability shortly after its disclosure. It's crucial for users and organizations to apply these patches promptly to protect their systems from potential exploitation. Additionally, network administrators can implement other security measures, such as firewall rules and network segmentation, to mitigate the risk of SMB-related attacks.

Commands used in this
nmap -p- 192.168.1.10 –min-rate=3000
nmap: This is the command-line utility for network discovery and security auditing.
-p-: This option tells Nmap to scan all 65535 TCP ports. The hyphen (-) indicates a range from port 1 to port 65535.
192.168.1.10: This is the target IP address that Nmap will scan.
--min-rate=3000: This option sets the minimum rate of packets sent per second during the scan. In this case, it's set to 3000 packets per second. This can help speed up the scan but may also increase network traffic and raise suspicion if done on networks where scanning activity is monitored.

nmap 192.168.1.10 -p135,139,445,49152-49157 -A –min-rate=3000
nmap: This is the command-line utility for network discovery and security auditing.
192.168.1.10: This is the target IP address that Nmap will scan.
-p135,139,445,49152-49157: This option specifies a specific list of TCP ports to scan. Ports 135, 139, 445, and the range from 49152 to 49157 will be scanned.
-A: This option enables aggressive scanning, which includes service version detection, OS detection, script scanning, and traceroute.
--min-rate=3000: This option sets the minimum rate of packets sent per second during the scan.

sudo nmap -sV –script vuln 192.168.1.10
sudo: This command is used to execute the subsequent command with superuser privileges, which may be necessary for certain operations, especially when performing network scans.

nmap: This is the command-line utility for network exploration and security auditing.

-sV: This option instructs Nmap to perform service version detection. Nmap will attempt to determine the versions of services running on open ports by analyzing their responses to specific probes.

--script vuln: This option specifies that Nmap should run vulnerability scripts against the target. Nmap has a collection of scripts designed to detect known vulnerabilities in various services and applications.

192.168.1.10: This is the target IP address that Nmap will scan for vulnerabilities.
