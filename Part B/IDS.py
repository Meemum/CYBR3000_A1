from scapy.all import *
import sys
import datetime
rules = []
packets = []

class Rule():
    def __init__(self) -> None:
        self._action = None
        self._type = None
        self._source_ip = None
        self._destination_ip = None
        self._source_port = None
        self._destination_port = None
        self._content = None
        self._msg = None
        self._flags = None
        self._count = None
        self._seconds = None

    def __str__(self) -> str:
        return f"Action: {self._action}\n\
Type: {self._type}.\n\
Source: {self._source_ip}:{self._source_port}\n\
Dest: {self._destination_ip}:{self._destination_port}\n\
Content: {self._content}\n\
Msg: {self._msg}\n\
Flags: {self._flags}\n\
Count: {self._count}\n\
Secs: {self._seconds}"
        
class PacketInfo():
    def __init__(self) -> None:
        self._type = None
        self._source_ip = None
        self._source_port = None
        self._destination_ip = None
        self._destination_port = None
        self._content = None
        self._flags = None

    def __str__(self) -> str:
        return f"Type: {self._type}\n\
Source: {self._source_ip}:{self._source_port}\n\
Dest: {self._destination_ip}:{self._destination_port}\n\
Content: {self._content}.\n\
Flags: {self._flags}\n"


def read_rules(ruleset_path: str):
    global rules

    rule_file = open(ruleset_path, "r")
    for line in rule_file:
        if line[0] != '#':
            r = Rule()
            ## set r appropriately
            linestr = line.split(" ")
            r._action = linestr[0]
            r._type = linestr[1]
            r._source_ip = linestr[2]
            r._source_port = linestr[3]
            r._destination_ip = linestr[5]
            r._destination_port = linestr[6]
            
            linestr2 = line.split("(")
            beepboop = linestr2[1]
            beepboop = beepboop[0:len(beepboop)-1]
            beepboop = beepboop.split("; ") 
            # i apologise for whatver on earth these variable names are
            # i was tired
    
            for s in beepboop:
                s = s.split(": ")
                if "content" in s:
                    if ";" in s[1]:
                        r._content = s[1][1:len(s[1])-2]
                    else:
                        r._content = s[1][1:len(s[1])-1]

                if "msg" in s:
                    if ";)" in s[1]:
                        r._msg = s[1][1:len(s[1])-3]
                    elif ";" in s[1]:
                        r._msg = s[1][1:len(s[1])-2]
                    else:
                        r._msg = s[1][1:len(s[1])-1]

                if "flags" in s:
                        r._flags = s[1][0]

                if "detection_filter" in s:
                    filter_info = s[1][0:len(s[1])-1]
                    filter_info = filter_info.split(", ")
                    for x in filter_info:
                        x= x.split(" ")
                        if "count" in x:
                            r._count = x[1]
                        if "seconds" in x:
                            r._seconds = x[1]
            rules.append(r)

    rule_file.close()
    

def read_packets(packet_path: str):
    global packets

    packet_list = rdpcap(packet_path)
    
    for packet in packet_list:
        p = PacketInfo()
        p._type = convert_type(packet.proto)
        p._source_ip = packet.src
        p._destination_ip = packet.dst
        p._source_port = str(getattr(packet, 'sport', "any"))
        p._destination_port = str(getattr(packet, 'dport', "any"))
        p._content = str(getattr(packet, 'load', None))
        if p._content is not None:
            p._content = p._content[2:len(p._content)-1]
        
        if p._type == "tcp":
            p._flags = str(getattr(packet[TCP], 'flags', None)) # type: ignore
        packets.append(p)

        
        
def convert_type(i: int) -> str:
    # helper to convert numeric to str for protocol name
    if i == 6:
        return "tcp"
    if i == 1:
        return "icmp"
    if i == 17:
        return "udp"
    

    


def apply_rules():
    global packets
    global rules

    log_file = open("IDS_log.txt","w")

    i=1
     
    for packet in packets:
        for rule in rules:
            
            # I  apologise for the following disaster
            # but couldnt figure out a better way
            if (rule._type in (packet._type, "ip")):
                if (rule._source_ip == packet._source_ip or rule._source_ip == "any"):
                    if (rule._source_port == packet._source_port or rule._source_port == "any"):
                        if (rule._destination_ip == packet._destination_ip or rule._destination_ip == "any"):
                            if (rule._destination_port == packet._destination_port or rule._destination_port == "any"):
                                
                                content_match = (rule._content is None or (packet._content == rule._content))
                                flags_match = (rule._flags is None or (packet._flags == rule._flags))
                                
                                # REF: the idea to use a variable to check if content and flags matched
                                # REF: was taken from ChatGPT.
                    
                                if content_match and flags_match:
                                    ## DETECTION FILTER STUFF!!!
                                    
                                    write_to_log(log_file, rule._msg)
                                    continue

    log_file.close()


def write_to_log(file, message):
    file.write(f"{datetime.datetime.now().replace(microsecond=0)} - Alert: {message}\n")


                                    
                                


def main():

    read_rules(sys.argv[2])
    read_packets(sys.argv[1])

    apply_rules()

    
    

if __name__ == "__main__":
    main()