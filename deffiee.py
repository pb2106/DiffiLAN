
#Deffie hellman
import socket
import random
import threading
import time
from tabulate import tabulate
import scapy.all as scapy

def get_network_range():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        default_mask = "255.255.255.0"
        ip_parts = local_ip.split('.')
        mask_parts = default_mask.split('.')
        binary_mask = ''.join(f"{int(octet):08b}" for octet in mask_parts)
        prefix_length = binary_mask.count('1')
        return f"{'.'.join(ip_parts[:3])}.0/{prefix_length}"
    except:
        return None

def get_lan_ips(network_range):
    arp_request = scapy.ARP(pdst=network_range)  
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  
    arp_request_broadcast = broadcast / arp_request  
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]  
    return [[received.psrc, received.hwsrc] for _, received in answered_list]

def main():
    network = get_network_range()
    if network:
        print(f"\n📡 Scanning Network: {network}")
        devices = get_lan_ips(network)
        if devices:
            print("\n🔎 Found Devices on LAN 🔎")
            print(tabulate(devices, headers=["IP Address", "MAC Address"], tablefmt="grid"))
        else:
            print("\n❌ No devices found.")
    else:
        print("\n⚠️ Could not determine network range.")

if __name__ == "__main__":
    main()


p = 23  
g = 5   

priv1 = int(input("Enter a private key: "))
x = g**priv1 % p

peer_public_key = None  
lock = threading.Lock()  

def send_key(sock):
    sock.sendall(str(x).encode())

def receive_key(sock):
    global peer_public_key
    peer_public_key = int(sock.recv(1024).decode())
    
def server_mode():
    global peer_public_key
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 12345))
    server.listen(1)
    print("[SERVER] Waiting for connection...")
    conn, addr = server.accept()
    print(f"[SERVER] Connected by {addr}")
    send_thread = threading.Thread(target=send_key, args=(conn,))
    receive_thread = threading.Thread(target=receive_key, args=(conn,))
    send_thread.start()
    receive_thread.start()
    send_thread.join()
    receive_thread.join()
    conn.close()
    server.close()

def client_mode(ip):
    global peer_public_key
    time.sleep(1)  
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((ip, 12345))
        print("[CLIENT] Connected to server")
        send_thread = threading.Thread(target=send_key, args=(sock,))
        receive_thread = threading.Thread(target=receive_key, args=(sock,))
        send_thread.start()
        receive_thread.start()
        send_thread.join()
        receive_thread.join()
        sock.close()

    except Exception as e:
        print(f"[CLIENT] Connection failed: {e}")

ip = input("Enter the peer's IP (leave blank if only running as server): ")
server_thread = threading.Thread(target=server_mode)
server_thread.start()

if ip:
    client_thread = threading.Thread(target=client_mode, args=(ip,))
    client_thread.start()
    client_thread.join()

server_thread.join()

if peer_public_key:
    shared_secret = peer_public_key**priv1%p
    print(f"Shared Secret Key: {shared_secret}")
else:
    print("Key exchange failed.")
