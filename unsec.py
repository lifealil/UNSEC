from scapy.all import *
import time

# --- Constants (using ALL_CAPS for convention) ---
# Dictionary of unsecured protocols and their default ports
UNSECURED_PROTOCOLS = {
    'HTTP': '80',   # Port for HTTP
    'FTP': '21',    # Port for FTP control
    'TELNET': '23', # Port for Telnet
    'SMTP': '25',   # Port for SMTP
    'POP3': '110',  # Port for POP3
    'IMAP': '143'   # Port for IMAP
}

# Number of packets to sniff by default
PACKET_COUNT = 150

# --- Packet Handler Functions ---
# Consolidated handler for various protocols
def generic_monitor(packet_list, protocol_name, detailed=False):
    """
    Generic handler to print packet summaries or detailed info.
    packet_list: A list of packets captured by sniff.
    protocol_name: The name of the protocol being monitored (e.g., 'HTTP', 'FTP').
    detailed: If True, prints packet.show() for detailed info; otherwise, packet.summary().
    """

    if not packet_list:
        print(f"No {protocol_name} packets captured.\n")
        return

    for p in packet_list:
        if detailed:
            print(f"--------------------> PACKET <--------------------\n{p.show()}\n")
        else:
            print(p.summary())
    print(f"\nMonitoring {protocol_name} traffic complete.")

def real_time_packet(packet, protocol_name, detailed_view):
    if detailed_view:
        print(f"--------------------> NEW PACKET ({protocol_name}) <--------------------\n{packet.show()}\n")
    else:
        print(f"[{protocol_name}] {packet.summary()}")

# --- Main Menu and Sniffing Logic ---
def main_menu():
    """
    Displays the main menu and handles user selection for traffic monitoring.
    """
    while True: # Loop to keep the menu running until 'exit'
        print("-" * 60)
        print("Select an option: \n")
        print("-- 1. HTTP Monitor (BASIC or ADVANCED)")
        print("-- 2. FTP Monitor")
        print("-- 3. TELNET Monitor")
        print("-- 4. SMTP Monitor")
        print("-- 5. POP3 Monitor")
        print("-- 6. IMAP Monitor")
        print("-- exit\n")

        selection = input("> ").strip().lower() # .strip() removes whitespace, .lower() for case-insensitivity
        time.sleep(0.5)

        if selection == "exit":
            print("\n----------> Exiting program! Goodbye!")
            break # Exit the loop and end the program

        print("----------> Starting Service...")
        print("-" * 60)
        time.sleep(1.5)

        protocol_to_monitor = None
        port_filter = None
        detailed_view = False
        

        # Determine protocol and port based on user selection
        if selection == "1":
            http_choice = input("Choose the HTTP method:\n-- 1. HTTP Monitor BASIC\n-- 2. HTTP Packet Monitor (Detailed)\n\n> ").strip()
            if http_choice == "1":
                protocol_to_monitor = "HTTP"
                port_filter = UNSECURED_PROTOCOLS['HTTP']
                detailed_view = False
            elif http_choice == "2":
                protocol_to_monitor = "HTTP"
                port_filter = UNSECURED_PROTOCOLS['HTTP']
                detailed_view = True
            else:
                print("Invalid HTTP option. Please try again.")
                continue # Go back to main menu
        elif selection == "2":
            protocol_to_monitor = "FTP"
            port_filter = UNSECURED_PROTOCOLS['FTP']
        elif selection == "3":
            protocol_to_monitor = "TELNET"
            port_filter = UNSECURED_PROTOCOLS['TELNET']
        elif selection == "4":
            protocol_to_monitor = "SMTP"
            port_filter = UNSECURED_PROTOCOLS['SMTP']
        elif selection == "5":
            protocol_to_monitor = "POP3"
            port_filter = UNSECURED_PROTOCOLS['POP3']
        elif selection == "6":
            protocol_to_monitor = "IMAP"
            port_filter = UNSECURED_PROTOCOLS['IMAP']
        else:
            print("Invalid selection. Please choose a number from 1 to 6, or 'exit'.")
            continue # Go back to main menu

        if protocol_to_monitor and port_filter:
            try:
                # Construct the filter string
                filter_string = f"tcp port {port_filter}"
                print(f"----------> Started Service: {protocol_to_monitor} monitor running!")
                print("-" * 60)
                print(f"Sniffing on filter: {filter_string} for {PACKET_COUNT} packets...\n")
                # Note: 'iface=""' means Scapy tries to find the default interface.
                # For specific interfaces, replace "" with your interface name (e.g., "eth0", "Wi-Fi").
                captured_packets = sniff(filter=filter_string, prn=functools.partial(real_time_packet, protocol_name=protocol_to_monitor, detailed_view=detailed_view), count=PACKET_COUNT, iface="")
                # Call the generic monitor with appropriate parameters
                generic_monitor(captured_packets, protocol_to_monitor, detailed=detailed_view)

            except PermissionError:
                print("\nError: Permission denied. You might need to run this script with root/administrator privileges.")
                print("On Linux/macOS: sudo python your_script_name.py")
                print("On Windows: Run your command prompt/PowerShell as Administrator.")
            except Exception as e:
                print(f"An unexpected error occurred during sniffing: {e}")
        else:
            print("Could not determine protocol or port to monitor. Please try again.")

# --- Start the application ---
if __name__ == "__main__":
    main_menu()
