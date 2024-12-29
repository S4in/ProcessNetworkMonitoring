import ctypes
import ctypes.util

# Find the pcap library (Npcap uses libpcap API)
# pcap_library_path = ctypes.util.find_library('wpcap')
pcap_library_path = "C:\\Windows\\System32\\Npcap\\wpcap.dll"
print(pcap_library_path)
if pcap_library_path is None:
    raise OSError("Npcap (wpcap.dll) not found")

# Load the Npcap library
pcap = ctypes.CDLL(pcap_library_path)
print(type(pcap))


class PcapIf(ctypes.Structure):
    pass


PcapIf._fields_ = [
    ('next', ctypes.POINTER(PcapIf)),
    ('name', ctypes.c_char_p),
    ('description', ctypes.c_char_p),
    # Other fields omitted for simplicity
]

# Define pcap_findalldevs signature
pcap.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(PcapIf)), ctypes.c_char_p]
pcap.pcap_findalldevs.restype = ctypes.c_int
pcap.pcap_freealldevs.argtypes = [ctypes.POINTER(PcapIf)]
pcap.pcap_freealldevs.restype = None


def list_devices():
    alldevs = ctypes.POINTER(PcapIf)()
    errbuf = ctypes.create_string_buffer(256)

    # Call pcap_findalldev
    result = pcap.pcap_findalldevs(ctypes.byref(alldevs), errbuf)
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
    print(f"Name: {device['name']}, Description: {device['description']}")

# Define pcap_open_live and pcap_next function signatures
pcap.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                ctypes.POINTER(ctypes.c_char)]
pcap.pcap_open_live.restype = ctypes.c_void_p

pcap.pcap_next.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.Structure)]
pcap.pcap_next.restype = ctypes.POINTER(ctypes.c_ubyte)


# Open a live capture on the first device
def capture_packets(device, packet_count=10):
    errbuf = ctypes.create_string_buffer(256)

    handle = pcap.pcap_open_live(device.encode(), 65536, 1, 1000, errbuf)
    if not handle:
        raise OSError(f"Failed to open device: {errbuf.value.decode()}")

    for _ in range(packet_count):
        header = ctypes.Structure()  # You need to define this structure based on pcap_pkthdr
        packet = pcap.pcap_next(handle, ctypes.byref(header))
        if packet:
            print("Packet received:", bytes(packet[:header.len]))

    pcap.pcap_close(handle)


# Capture packets on the first device
capture_packets(devices[0]["name"])
