from pywifi import PyWiFi
import time

def get_wifi_interface():
    wifi = PyWiFi()
    interfaces = wifi.interfaces()
    if len(interfaces) <= 0:
        print "Wireless card interface not found!"
        exit()
    if len(interfaces) == 1:
        return wifi.interfaces[0]
    else:
        for i, w in enumerate(interfaces):
            print '%-4s   %s' %(i, w.name())
        while True:
            iface_no = raw_input('Please select network card interface '.decode('utf-8').encode('gbk')) 
            no = int(iface_no)
            if no >= 0 and no < len(interfaces):
                return interfaces[no]   


def scan(face):
    face.scan()
    time.sleep(2)
    return face.scan_results()


if __name__ == '__main__':        
    face = get_wifi_interface()
    results = scan(face)
    for i in results:
        print(i.bssid, i.ssid)