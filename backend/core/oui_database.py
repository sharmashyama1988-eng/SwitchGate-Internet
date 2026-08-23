"""
SwitchGate - MAC OUI Vendor Resolver & Smart Device Categorizer
Maps hardware MAC address prefixes to manufacturers and infers human-friendly device types.
"""
from typing import Tuple

# Curated High-Frequency OUI Lookup Table (Top consumer brands, TVs, phones, routers, IoT)
OUI_TABLE = {
    # Apple
    "00:03:93": ("Apple", "apple"),
    "00:05:02": ("Apple", "apple"),
    "00:0a:95": ("Apple", "apple"),
    "00:10:fa": ("Apple", "apple"),
    "00:14:51": ("Apple", "apple"),
    "00:16:cb": ("Apple", "apple"),
    "00:17:f2": ("Apple", "apple"),
    "00:19:e3": ("Apple", "apple"),
    "00:1b:63": ("Apple", "apple"),
    "00:1c:b3": ("Apple", "apple"),
    "00:1d:4f": ("Apple", "apple"),
    "00:1e:52": ("Apple", "apple"),
    "00:1e:c2": ("Apple", "apple"),
    "00:21:e9": ("Apple", "apple"),
    "00:22:41": ("Apple", "apple"),
    "00:23:12": ("Apple", "apple"),
    "00:23:df": ("Apple", "apple"),
    "00:24:36": ("Apple", "apple"),
    "00:25:00": ("Apple", "apple"),
    "00:25:4b": ("Apple", "apple"),
    "00:26:08": ("Apple", "apple"),
    "00:26:b0": ("Apple", "apple"),
    "00:88:65": ("Apple", "apple"),
    "04:0c:ce": ("Apple", "apple"),
    "04:15:52": ("Apple", "apple"),
    "04:26:65": ("Apple", "apple"),
    "04:4b:ed": ("Apple", "apple"),
    "04:54:53": ("Apple", "apple"),
    "04:69:f8": ("Apple", "apple"),
    "04:db:56": ("Apple", "apple"),
    "04:e5:36": ("Apple", "apple"),
    "04:f1:3e": ("Apple", "apple"),
    "08:66:98": ("Apple", "apple"),
    "08:70:45": ("Apple", "apple"),
    "08:74:02": ("Apple", "apple"),
    "10:1c:0c": ("Apple", "apple"),
    "10:40:f3": ("Apple", "apple"),
    "10:93:e9": ("Apple", "apple"),
    "10:9a:dd": ("Apple", "apple"),
    "14:10:9f": ("Apple", "apple"),
    "14:20:5e": ("Apple", "apple"),
    "14:7d:da": ("Apple", "apple"),
    "14:99:e2": ("Apple", "apple"),
    "18:af:61": ("Apple", "apple"),
    "18:e7:28": ("Apple", "apple"),
    "1c:1a:c0": ("Apple", "apple"),
    "20:7d:74": ("Apple", "apple"),
    "24:a0:74": ("Apple", "apple"),
    "24:ab:81": ("Apple", "apple"),
    "28:0b:5c": ("Apple", "apple"),
    "28:6a:ba": ("Apple", "apple"),
    "28:cf:e9": ("Apple", "apple"),
    "30:07:4d": ("Apple", "apple"),
    "34:08:bc": ("Apple", "apple"),
    "34:12:98": ("Apple", "apple"),
    "38:ca:da": ("Apple", "apple"),
    "3c:07:54": ("Apple", "apple"),
    "3c:15:c2": ("Apple", "apple"),
    "3c:22:fb": ("Apple", "apple"),
    "40:6c:8f": ("Apple", "apple"),
    "40:98:ad": ("Apple", "apple"),
    "44:00:10": ("Apple", "apple"),
    "48:d7:05": ("Apple", "apple"),
    "4c:57:ca": ("Apple", "apple"),
    "50:bc:96": ("Apple", "apple"),
    "54:26:96": ("Apple", "apple"),
    "54:72:4f": ("Apple", "apple"),
    "58:40:4e": ("Apple", "apple"),
    "5c:95:ae": ("Apple", "apple"),
    "60:03:08": ("Apple", "apple"),
    "64:a3:41": ("Apple", "apple"),
    "68:9c:70": ("Apple", "apple"),
    "70:11:24": ("Apple", "apple"),
    "74:e1:b6": ("Apple", "apple"),
    "78:7b:8a": ("Apple", "apple"),
    "7c:6d:62": ("Apple", "apple"),
    "80:49:71": ("Apple", "apple"),
    "88:66:a5": ("Apple", "apple"),
    "8c:85:90": ("Apple", "apple"),
    "90:72:40": ("Apple", "apple"),
    "94:94:26": ("Apple", "apple"),
    "98:01:a7": ("Apple", "apple"),
    "9c:20:7b": ("Apple", "apple"),
    "a4:83:e7": ("Apple", "apple"),
    "a8:51:ab": ("Apple", "apple"),
    "ac:bc:32": ("Apple", "apple"),
    "b0:34:95": ("Apple", "apple"),
    "b4:18:d1": ("Apple", "apple"),
    "b8:09:8a": ("Apple", "apple"),
    "bc:d0:74": ("Apple", "apple"),
    "c0:84:7a": ("Apple", "apple"),
    "c8:69:cd": ("Apple", "apple"),
    "cc:08:8d": ("Apple", "apple"),
    "d0:25:98": ("Apple", "apple"),
    "d4:61:9d": ("Apple", "apple"),
    "d8:9e:3f": ("Apple", "apple"),
    "dc:a9:04": ("Apple", "apple"),
    "e0:b9:ba": ("Apple", "apple"),
    "e4:9a:dc": ("Apple", "apple"),
    "e8:80:2e": ("Apple", "apple"),
    "f0:18:98": ("Apple", "apple"),
    "f4:5c:89": ("Apple", "apple"),
    "f8:ff:c2": ("Apple", "apple"),
    "fc:e9:98": ("Apple", "apple"),

    # Samsung
    "00:07:ab": ("Samsung Electronics", "samsung"),
    "00:12:47": ("Samsung Electronics", "samsung"),
    "00:15:99": ("Samsung Electronics", "samsung"),
    "00:17:c9": ("Samsung Electronics", "samsung"),
    "00:1a:8a": ("Samsung Electronics", "samsung"),
    "00:1d:25": ("Samsung Electronics", "samsung"),
    "00:21:19": ("Samsung Electronics", "samsung"),
    "00:23:39": ("Samsung Electronics", "samsung"),
    "00:24:54": ("Samsung Electronics", "samsung"),
    "00:26:37": ("Samsung Electronics", "samsung"),
    "08:37:3d": ("Samsung Electronics", "samsung"),
    "10:30:47": ("Samsung Electronics", "samsung"),
    "14:49:e0": ("Samsung Electronics", "samsung"),
    "18:26:66": ("Samsung Electronics", "samsung"),
    "20:55:31": ("Samsung Electronics", "samsung"),
    "24:4b:03": ("Samsung Electronics", "samsung"),
    "28:98:7b": ("Samsung Electronics", "samsung"),
    "30:07:4d": ("Samsung Electronics", "samsung"),
    "34:23:87": ("Samsung Electronics", "samsung"),
    "38:0b:40": ("Samsung Electronics", "samsung"),
    "40:0e:85": ("Samsung Electronics", "samsung"),
    "44:91:60": ("Samsung Electronics", "samsung"),
    "48:44:f7": ("Samsung Electronics", "samsung"),
    "50:85:69": ("Samsung Electronics", "samsung"),
    "54:92:be": ("Samsung Electronics", "samsung"),
    "58:c3:8b": ("Samsung Electronics", "samsung"),
    "60:6b:bd": ("Samsung Electronics", "samsung"),
    "68:eb:ae": ("Samsung Electronics", "samsung"),
    "78:47:1d": ("Samsung Electronics", "samsung"),
    "84:25:db": ("Samsung Electronics", "samsung"),
    "88:32:9b": ("Samsung Electronics", "samsung"),
    "90:f1:aa": ("Samsung Electronics", "samsung"),
    "98:83:89": ("Samsung Electronics", "samsung"),
    "a4:70:d6": ("Samsung Electronics", "samsung"),
    "a8:06:00": ("Samsung Electronics", "samsung"),
    "b0:ec:e1": ("Samsung Electronics", "samsung"),
    "b8:57:d8": ("Samsung Electronics", "samsung"),
    "bc:44:86": ("Samsung Electronics", "samsung"),
    "c4:73:1e": ("Samsung Electronics", "samsung"),
    "cc:07:ab": ("Samsung Electronics", "samsung"),
    "d0:59:e4": ("Samsung Electronics", "samsung"),
    "d8:57:ef": ("Samsung Electronics", "samsung"),
    "e4:58:b8": ("Samsung Electronics", "samsung"),
    "e8:e5:d6": ("Samsung Electronics", "samsung"),
    "f0:5b:7b": ("Samsung Electronics", "samsung"),
    "f4:7b:5e": ("Samsung Electronics", "samsung"),
    "fc:a1:3e": ("Samsung Electronics", "samsung"),

    # LG Electronics (Smart TVs, Appliances)
    "00:1f:6b": ("LG Electronics", "tv"),
    "00:26:e2": ("LG Electronics", "tv"),
    "10:68:3f": ("LG Electronics", "tv"),
    "20:3d:66": ("LG Electronics", "tv"),
    "2c:54:cf": ("LG Electronics", "tv"),
    "30:75:12": ("LG Electronics", "tv"),
    "40:b0:fa": ("LG Electronics", "tv"),
    "58:a2:b5": ("LG Electronics", "tv"),
    "64:99:5d": ("LG Electronics", "tv"),
    "74:a7:22": ("LG Electronics", "tv"),
    "88:c9:d0": ("LG Electronics", "tv"),
    "a8:23:fe": ("LG Electronics", "tv"),
    "b8:ad:3e": ("LG Electronics", "tv"),
    "c4:36:6c": ("LG Electronics", "tv"),
    "dc:0b:34": ("LG Electronics", "tv"),
    "e8:5b:5b": ("LG Electronics", "tv"),

    # Sony (PlayStation, BRAVIA Smart TVs)
    "00:04:1f": ("Sony Interactive / TV", "console"),
    "00:13:15": ("Sony Interactive", "console"),
    "00:1d:0d": ("Sony Interactive", "console"),
    "00:24:8d": ("Sony Electronics", "tv"),
    "28:0d:fc": ("Sony Interactive", "console"),
    "70:9e:29": ("Sony Interactive", "console"),
    "a8:e3:ee": ("Sony BRAVIA TV", "tv"),
    "f8:46:1c": ("Sony Interactive", "console"),
    "fc:0f:e6": ("Sony Electronics", "tv"),

    # Amazon (Echo, Alexa, Fire TV, Kindle)
    "00:bb:3a": ("Amazon Technologies", "iot"),
    "18:74:2e": ("Amazon Fire TV", "tv"),
    "34:d2:70": ("Amazon Echo", "iot"),
    "38:f7:3d": ("Amazon Technologies", "iot"),
    "40:b4:cd": ("Amazon Echo / Alexa", "iot"),
    "44:65:0d": ("Amazon Fire TV", "tv"),
    "50:f5:da": ("Amazon Technologies", "iot"),
    "68:37:e9": ("Amazon Echo", "iot"),
    "74:75:48": ("Amazon Technologies", "iot"),
    "ac:63:be": ("Amazon Fire Stick", "tv"),
    "cc:9e:a2": ("Amazon Echo Dot", "iot"),
    "f0:27:2d": ("Amazon Echo / Fire", "tv"),
    "fc:a6:67": ("Amazon Technologies", "iot"),

    # Google (Chromecast, Pixel, Google Home, Nest)
    "00:1a:11": ("Google LLC", "phone"),
    "1c:56:fe": ("Google Nest Hub", "iot"),
    "3c:5a:37": ("Google Chromecast", "tv"),
    "48:d6:d5": ("Google LLC", "phone"),
    "54:60:09": ("Google Home", "iot"),
    "64:16:66": ("Google Pixel", "phone"),
    "94:eb:2c": ("Google Nest", "iot"),
    "a4:77:33": ("Google Chromecast", "tv"),
    "d8:6c:63": ("Google LLC", "phone"),
    "f4:03:04": ("Google Home / Nest", "iot"),

    # Xiaomi / Redmi / POCO
    "00:ec:0a": ("Xiaomi", "phone"),
    "18:59:36": ("Xiaomi Communications", "phone"),
    "28:6c:07": ("Xiaomi Smart Home", "iot"),
    "34:80:0d": ("Xiaomi Mi TV", "tv"),
    "50:64:2b": ("Xiaomi Communications", "phone"),
    "64:09:80": ("Xiaomi", "phone"),
    "74:23:44": ("Xiaomi", "phone"),
    "7c:49:eb": ("Xiaomi Communications", "phone"),
    "88:c3:97": ("Xiaomi Mi TV Stick", "tv"),
    "98:fa:9b": ("Xiaomi", "phone"),
    "a4:c4:94": ("Xiaomi Smart Device", "iot"),
    "c4:0b:d3": ("Xiaomi", "phone"),
    "d4:97:0b": ("Xiaomi", "phone"),
    "f0:18:98": ("Xiaomi", "phone"),

    # OnePlus / Oppo / Vivo / Realme (BBK)
    "14:ab:c5": ("OnePlus Technology", "phone"),
    "2c:59:8a": ("OnePlus", "phone"),
    "50:32:75": ("OnePlus Technology", "phone"),
    "64:cc:2e": ("OPPO Mobile", "phone"),
    "88:d4:7e": ("Vivo Mobile", "phone"),
    "94:87:e0": ("Realme Mobile", "phone"),
    "a0:93:47": ("OPPO Mobile", "phone"),
    "c8:25:27": ("OnePlus", "phone"),

    # Roku
    "08:05:81": ("Roku Inc.", "tv"),
    "20:df:b9": ("Roku Streaming Player", "tv"),
    "2c:aa:8e": ("Roku TV", "tv"),
    "84:ea:ed": ("Roku TV", "tv"),
    "ac:3a:7a": ("Roku Inc.", "tv"),
    "b0:a7:37": ("Roku Streaming Stick", "tv"),
    "d8:31:34": ("Roku Inc.", "tv"),

    # TP-Link / D-Link / Netgear / Tenda / Asus / Cisco (Routers & Repeaters)
    "00:1d:7e": ("Cisco-Linksys", "router"),
    "00:24:8c": ("ASUSTeK Computer", "laptop"),
    "04:18:d6": ("Ubiquiti Networks", "router"),
    "0c:80:63": ("TP-Link Technologies", "router"),
    "14:cc:20": ("TP-Link Technologies", "router"),
    "1c:7e:e5": ("D-Link International", "router"),
    "20:4e:7f": ("Netgear", "router"),
    "28:28:5d": ("TP-Link Smart Bulb", "iot"),
    "30:de:4b": ("TP-Link Technologies", "router"),
    "50:c7:bf": ("TP-Link Tapo Smart Camera", "iot"),
    "54:af:97": ("Netgear", "router"),
    "60:32:b1": ("TP-Link", "router"),
    "70:4f:57": ("TP-Link", "router"),
    "84:16:f9": ("TP-Link", "router"),
    "98:de:d0": ("TP-Link", "router"),
    "a0:f3:c1": ("TP-Link", "router"),
    "c0:06:c3": ("Netgear", "router"),
    "c4:e9:84": ("TP-Link", "router"),
    "cc:32:e5": ("TP-Link", "router"),
    "e8:48:b8": ("TP-Link", "router"),

    # PC / Laptops (Intel, Dell, HP, Lenovo, Microsoft, Realtek)
    "00:15:5d": ("Microsoft Hyper-V / Surface", "laptop"),
    "00:1b:21": ("Intel Corporate", "laptop"),
    "00:21:6a": ("Intel Corporate", "laptop"),
    "00:27:0e": ("Intel Corporate", "laptop"),
    "18:66:da": ("Dell Inc.", "laptop"),
    "28:18:78": ("Microsoft Surface", "laptop"),
    "34:17:eb": ("Dell Inc.", "laptop"),
    "3c:18:a0": ("HP Inc.", "laptop"),
    "48:2a:e3": ("Lenovo PC", "laptop"),
    "54:ee:75": ("Dell Inc.", "laptop"),
    "68:05:ca": ("Intel Corporation", "laptop"),
    "70:85:c2": ("HP Inc.", "laptop"),
    "8c:16:45": ("Lenovo PC", "laptop"),
    "98:e7:43": ("HP Inc.", "laptop"),
    "a4:bb:6d": ("Dell Inc.", "laptop"),
    "b8:85:84": ("Lenovo PC", "laptop"),
    "c8:5b:76": ("HP Inc.", "laptop"),
    "d8:9c:e0": ("Dell Inc.", "laptop"),
    "e0:d5:5e": ("Dell Inc.", "laptop"),
    "f0:1f:af": ("Dell Inc.", "laptop"),

    # IoT / Smart Home (Espressif ESP32/ESP8266, Tuya, Raspberry Pi, Sonos)
    "18:fe:34": ("Espressif IoT Chip", "iot"),
    "24:0a:c4": ("Espressif IoT (Smart Light)", "iot"),
    "24:62:ab": ("Espressif IoT", "iot"),
    "24:6f:28": ("Espressif ESP32", "iot"),
    "28:cd:c1": ("Tuya Smart IoT", "iot"),
    "2c:f4:32": ("Espressif IoT", "iot"),
    "30:ae:a4": ("Espressif ESP32", "iot"),
    "50:02:91": ("Sonos Speaker", "iot"),
    "5c:cf:7f": ("Espressif IoT", "iot"),
    "68:c6:3a": ("Tuya Smart Plug", "iot"),
    "80:7d:3a": ("Tuya Smart Life", "iot"),
    "84:0d:8e": ("Tuya Smart Device", "iot"),
    "84:f3:eb": ("Espressif ESP8266", "iot"),
    "94:b9:7e": ("Sonos Speaker", "iot"),
    "a4:cf:12": ("Espressif IoT", "iot"),
    "b8:27:eb": ("Raspberry Pi", "iot"),
    "dc:a6:32": ("Raspberry Pi 4", "iot"),
    "e8:eb:11": ("Raspberry Pi 5", "iot"),
}

def resolve_vendor_and_category(mac: str, hostname: str = "", ip: str = "") -> Tuple[str, str, str]:
    """
    Resolves MAC OUI, Hostname, and IP to determine:
    1. Clean Vendor Name (e.g., 'Apple', 'LG Electronics', 'Samsung')
    2. Category Icon Code ('phone', 'tv', 'laptop', 'console', 'iot', 'router', 'unknown')
    3. Suggested Friendly Name (e.g., "Living Room Smart TV", "Papa's iPhone", "Work Laptop")
    """
    mac_clean = mac.lower().replace("-", ":").strip()
    prefix = ":".join(mac_clean.split(":")[:3])
    
    vendor = "Generic Device"
    category = "unknown"
    
    # 1. Match from OUI table
    if prefix in OUI_TABLE:
        v_name, cat = OUI_TABLE[prefix]
        vendor = v_name
        category = cat
    
    # 2. Hostname heuristic enrichment
    h_lower = hostname.lower() if hostname else ""
    
    if "iphone" in h_lower:
        vendor = "Apple"
        category = "phone"
    elif "ipad" in h_lower:
        vendor = "Apple"
        category = "phone" # tablet/mobile
    elif "macbook" in h_lower or "imac" in h_lower:
        vendor = "Apple"
        category = "laptop"
    elif "tv" in h_lower or "webos" in h_lower or "bravia" in h_lower or "tizen" in h_lower or "firestick" in h_lower or "chromecast" in h_lower or "roku" in h_lower:
        category = "tv"
    elif "playstation" in h_lower or "ps5" in h_lower or "ps4" in h_lower or "xbox" in h_lower or "nintendo" in h_lower or "switch" in h_lower:
        category = "console"
    elif "galaxy" in h_lower or "pixel" in h_lower or "oneplus" in h_lower or "redmi" in h_lower or "android" in h_lower:
        category = "phone"
    elif "desktop" in h_lower or "laptop" in h_lower or "win" in h_lower or "thinkpad" in h_lower:
        category = "laptop"
    elif "esp_" in h_lower or "tapo" in h_lower or "sonoff" in h_lower or "alexa" in h_lower or "echo" in h_lower or "tuya" in h_lower or "shelly" in h_lower or "printer" in h_lower:
        category = "iot"
    elif "router" in h_lower or "gateway" in h_lower or ip.endswith(".1"):
        category = "router"

    # 3. Generate Friendly Default Name
    if hostname and hostname not in ["*", "unknown", "localhost"]:
        friendly_name = hostname.replace(".local", "").replace(".lan", "").replace("-", " ").title()
    else:
        # Construct based on Category & Vendor
        if category == "tv":
            friendly_name = f"{vendor} Smart TV"
        elif category == "phone":
            friendly_name = f"{vendor} Smartphone"
        elif category == "laptop":
            friendly_name = f"{vendor} PC/Laptop"
        elif category == "console":
            friendly_name = f"{vendor} Gaming Console"
        elif category == "iot":
            friendly_name = f"{vendor} Smart Device"
        elif category == "router":
            friendly_name = "Main Wi-Fi Gateway"
        else:
            friendly_name = f"{vendor} ({ip.split('.')[-1] if ip else 'Device'})"

    return vendor, category, friendly_name
