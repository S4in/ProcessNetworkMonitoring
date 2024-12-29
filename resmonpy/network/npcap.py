from ctypes import (
    CDLL,
    c_int,
    c_uint,
    c_ushort,
    c_char,
    c_char_p,
    c_void_p,
    c_ubyte,
    Structure,
    POINTER,
    create_string_buffer,
    byref
)

pcap_library_path = "C:\\Windows\\System32\\Npcap\\wpcap.dll"
print(pcap_library_path)
if pcap_library_path is None:
    raise OSError("Npcap (wpcap.dll) not found")

# Load the Npcap library
pcap = CDLL(pcap_library_path)

bpf_u_int32 = c_uint


class SockAddr(Structure):
    pass


SockAddr._field_ = [
    ('sa_family', c_ushort),
    ('sa_data', c_char * 14)
]


class PcapAddr(Structure):
    pass


PcapAddr._field_ = [
    ('next', POINTER(PcapAddr)),
    ('addr',)
]


class PcapIf(Structure):
    pass


PcapIf._fields_ = [
    ('next', POINTER(PcapIf)),
    ('name', c_char_p),
    ('description', c_char_p),
    # Other fields omitted for simplicity
]

pcap.pcap_findalldevs.argtypes = [POINTER(POINTER(PcapIf)), c_char_p]
pcap.pcap_findalldevs.restype = c_int
pcap.pcap_freealldevs.argtypes = [POINTER(PcapIf)]
pcap.pcap_freealldevs.restype = None



def list_devices():
    alldevs = POINTER(PcapIf)()
    errbuf = create_string_buffer(256)

    # Call pcap_findalldev
    result = pcap.pcap_findalldevs(byref(alldevs), errbuf)
    if result != 0:
        raise OSError(f"Error finding devices")

        # Iterate through the device list
    devices = []
    dev = alldevs
    try:
        while dev:
            name = dev.contents.name
            description = dev.contents.description
            devices.append({
                'name': name.decode() if name else "No name",
                'description': description.decode() if description else "No description"
            })
            dev = dev.contents.next
    except Exception as e:
        print(f"Error processing device list: {e}")
    finally:
        if alldevs:
            pcap.pcap_freealldevs(alldevs)

    return devices


# Test the function
devices = list_devices()
for device in devices:
    print(f"Name: {device['name']}, Description: {device['description']}"


