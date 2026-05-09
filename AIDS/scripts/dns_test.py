"""Quick diagnostic: check if DNS packets from clients are visible."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scapy.all import sniff, IP, UDP, DNS, DNSQR, Raw, TCP

print("Listening for DNS (port 53) and TLS SNI on ALL interfaces...")
print("Browse a website on the client laptop now.")
print("Press Ctrl+C to stop.\n")

count = {"dns": 0, "tls": 0}

def extract_sni(raw_data):
    """Extract SNI from TLS ClientHello."""
    try:
        if raw_data[0] != 0x16:  # Not TLS handshake
            return None
        # Skip TLS record header (5 bytes) + handshake header (4 bytes)
        # + version (2) + random (32) 
        pos = 5 + 4 + 2 + 32
        # Session ID length
        sid_len = raw_data[pos]
        pos += 1 + sid_len
        # Cipher suites length
        cs_len = int.from_bytes(raw_data[pos:pos+2], 'big')
        pos += 2 + cs_len
        # Compression methods length
        cm_len = raw_data[pos]
        pos += 1 + cm_len
        # Extensions length
        ext_len = int.from_bytes(raw_data[pos:pos+2], 'big')
        pos += 2
        end = pos + ext_len
        while pos < end:
            ext_type = int.from_bytes(raw_data[pos:pos+2], 'big')
            ext_data_len = int.from_bytes(raw_data[pos+2:pos+4], 'big')
            pos += 4
            if ext_type == 0:  # SNI extension
                # SNI list length (2) + type (1) + name length (2) + name
                sni_list_len = int.from_bytes(raw_data[pos:pos+2], 'big')
                sni_type = raw_data[pos+2]
                sni_len = int.from_bytes(raw_data[pos+3:pos+5], 'big')
                sni = raw_data[pos+5:pos+5+sni_len].decode('ascii', errors='ignore')
                return sni
            pos += ext_data_len
    except (IndexError, ValueError):
        pass
    return None

def on_packet(pkt):
    if not pkt.haslayer(IP):
        return
    
    src = pkt[IP].src
    dst = pkt[IP].dst
    
    # Check DNS queries (port 53)
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        if pkt[DNS].qr == 0:
            domain = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            count["dns"] += 1
            print(f"  [DNS] {src} -> {dst} : {domain}")
    
    # Check TLS ClientHello for SNI (port 443)
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        if pkt[TCP].dport == 443:
            raw = bytes(pkt[Raw].load)
            if len(raw) > 5 and raw[0] == 0x16:  # TLS handshake
                sni = extract_sni(raw)
                if sni:
                    count["tls"] += 1
                    print(f"  [TLS SNI] {src} -> {dst} : {sni}")

try:
    sniff(prn=on_packet, store=False, timeout=60)
except KeyboardInterrupt:
    pass

print(f"\nResults: {count['dns']} DNS queries, {count['tls']} TLS SNI domains found")
if count['dns'] == 0 and count['tls'] > 0:
    print(">> Client uses DNS-over-HTTPS. DNS port 53 is encrypted.")
    print(">> Solution: Use TLS SNI extraction instead.")
elif count['dns'] == 0 and count['tls'] == 0:
    print(">> No DNS or TLS traffic seen. Check if client is connected.")
