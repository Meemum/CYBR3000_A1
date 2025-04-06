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


def readRules(ruleset_path: str):
    global rules

    # with open(file, operation) is much safer than file.open, file.write and file.close
    with open(ruleset_path, "r") as rule_file:
        for line in rule_file:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            rule = Rule()

            # Parse the basic rule components
            parts = line.split(" ")
            basic_rule_fields = {
                0: "_action",
                1: "_type",
                2: "_source_ip",
                3: "_source_port",
                5: "_destination_ip",
                6: "_destination_port",
            }
            for index, attr in basic_rule_fields.items():
                setattr(rule, attr, parts[index])


            try:
                options_part = line.split("(", 1)[1].rstrip(")")
                options = options_part.split("; ")
            except IndexError:
                continue  # skip malformed rule lines

            # Define attribute setters to avoid excessive elif statements
            # Applies logic in a more pythonic approach 
            option_setters = {
                "content": lambda v: setattr(rule, "_content", v),
                "msg": lambda v: setattr(rule, "_msg", v.rstrip(");")),
                "flags": lambda v: setattr(rule, "_flags", v[0]),
                # detection_filter handled separately
            }

            for option in options:
                if ": " not in option:
                    continue
                key, value = option.split(": ", 1)
                value = value.strip().strip('"')

                if key in option_setters:
                    option_setters[key](value)
                elif key == "detection_filter":
                    filter_items = value.rstrip(";").split(", ")
                    for item in filter_items:
                        filter_key, filter_value = item.split(" ")
                        if filter_key == "count":
                            rule._count = filter_value
                        elif filter_key == "seconds":
                            rule._seconds = filter_value

            rules.append(rule)


def readPackets(packet_path: str):
    global packets

    packet_list = rdpcap(packet_path)
    
    for packet in packet_list:
        p = PacketInfo()
        p._type = convertType(packet.proto)
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


def convertType(i: int) -> str:
    # Map numeric to str for protocol name
    protocol_map = {
        6: "tcp",
        1: "icmp",
        17: "udp"
    }
    
    # Return the protocol name, or "unknown" if the protocol is not in the map
    return protocol_map.get(i, "unknown")


def applyRules():
    global packets
    global rules

    # with open(file, operation) is much safer than file.open, file.write and file.close
    with open("IDS_log.txt", "w") as log_file:
        i = 1
    
        for packet in packets:
            for rule in rules:
                # Use AND operations to validate each content and flag match
                if (
                    rule._type in (packet._type, "ip") and
                    (rule._source_ip == packet._source_ip or rule._source_ip == "any") and
                    (rule._source_port == packet._source_port or rule._source_port == "any") and
                    (rule._destination_ip == packet._destination_ip or rule._destination_ip == "any") and
                    (rule._destination_port == packet._destination_port or rule._destination_port == "any")
                ):
                    content_match = (rule._content is None or packet._content == rule._content)
                    flags_match = (rule._flags is None or packet._flags == rule._flags)
    
                    if content_match and flags_match:
                        ## DETECTION FILTER STUFF!!!
                        writeLogs(rule._msg)
                        continue


def writeLogs(message):
    # with open(file, operation) is much safer than file.open, file.write and file.close
    with open("IDS_log.txt", "a") as file:
        file.write(f"{datetime.datetime.now().replace(microsecond=0)} - Alert: {message}\n")


def main():
    readRules(sys.argv[2])
    readPackets(sys.argv[1])
    applyRules()


if __name__ == "__main__":
    main()
