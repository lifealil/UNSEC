from scapy.all import *
import time

# Starting monitor HTTP traffic on port 80 with basic informations
def http_monitorBasic(packet):
    for p in packet:
        print(p.summary())
    
# Starting monitor HTTP traffic on port 80 showing packets informations
def http_monitorPacket(packet):
    for p in packet:
        print(f"--------------------> PACKET <--------------------\n{p.show()}\n")


# Main menu
def mainMenu():
    print("-" * 60)
    selection = input("Select an option: \n\n-- 1.HTTP Monitor BASIC:\n-- 2.HTTP Monitor Packets:\n-- exit\n\n> ")
    time.sleep(0.5)

    if selection == "exit":
        print("\n----------> Exiting program!")
        return
    
    print("---------> Starting Service...")
    print("-"*60)
    time.sleep(1.5)
    print("---------> Service Started!")
    print("\nMonitoring HTTP TRAFFIC:\n")

    try:
        if selection == "1":
            packet = sniff(filter="tcp port 80", prn=http_monitorBasic, count=150, iface="")
            mainMenu()
        elif selection == "2":
            packet = sniff(filter="tcp port 80", prn=http_monitorPacket, count=150, iface="")
            mainMenu()
                
    except Exception as e:
        print(f"Error selecting option or during sniff: {e}")
        

mainMenu()