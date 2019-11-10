INTRODUCTION 
    A sniffer is an application or device that can read, monitor, and capture network data exchanges and read network packets. 
    If the packets are not encrypted, a sniffer provides a full view of the data inside the packet. 
    Attacker store the incoming and outgoing data into the packet using network sniffer tool. 
    Apart from network sniffer, lots of packet sniffer and packet analysis tools is available which is used to check the sniffed packed. 
    A sniffer (packet sniffer) is a tool that intercepts data flowing in a network. If computers are connected to a local area network that 
    is not filtered or switched, the traffic can be broadcast to all computers contained in the same segment. This doesn’t generally occur, 
    since computers are generally told to ignore all the comings and goings of traffic from other computers. However, in the case of a sniffer, 
    all traffic is shared when the sniffer software commands the Network Interface Card (NIC) to stop ignoring the traffic. The NIC is put into
    promiscuous mode, and it reads communications between computers within a particular segment. This allows the sniffer to seize everything that is flowing in the network, which can lead to the unauthorized access of sensitive data. 
    A packet sniffer can take the form of either a hardware or software solution. A sniffer is also known as a packet analyser.

PROJECT
    This College Project is an attempt to remake the Simplified packet Sniffer in Python3 from Scratch. The goal is to Understand the working of the packet sniffer form inside using socket programming.  Upto this point of time the project is able disect the packet upto layer 4 (that is,
    Transport Layer). 

FUTURE SCOPE
    This Include packet disesction upto layer 7(that is, Application Layer).
    User friendly UI.Tracing the Particular packet stream of UDP and TCP.
    Compatibility with Windows.
    (Future Scope is subjected to change according to the achieved milestone).

TECHNICAL SPECIFICATION:
    FRONTEND:
        Python 3.6.1 and Tkinter GUI programming framework
    BACKEND:
        Python 3.6.1 and Socket programming

HARDWARE REQUIREMENTS:
		1)Any NIC/Ethernet enabled Computer/Laptop
		2)That Computer must be in a network or connect to internet.

SOFTWARE REQUIREMENTS:
		1)Any Linux OS with Command line Terminal (Can't be run on windows due to permission issue of creating sockets)
		2)Python 3 and above (preffered python3.6)

HOW TO RUN:
        1)Put The file in any linux directory and open command terminal from that directory.
        2)Type in the linux terminal without Quotes > "sudo python3 PacketSniffer.py"
        3)To exit the sniffer press from keyboard "ctrl+z".
REFERNCE:
    All the information used to make this project is available in the internet.

DISCLAIMER:
    All information and content contained in this Project are provided solely for Educational information and reference. Authors make no statement, representation, warranty or guarantee as to the accuracy or timeliness of the information and content contained in this Project. 

    Authors do not accept any responsibility or liability for any direct or indirect loss or damage which may be suffered or occasioned by this project howsoever arising due to any inaccuracy, omission, misrepresentation or error in respect of any information and content provided by this project.All through it provides you 99% accurate results under normal conditions.
 
 COPYRIGHT:
    All the content used in this project is taken from open source portals.Fork this Project if you are interseted in the python socket programming and want to Understand the networking more in details.