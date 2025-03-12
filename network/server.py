from scapy.all import ICMP, sniff   
from cryptography.fernet import Fernet

# Pre-shared symmetric key for decryption
# Generate a random key
# KEY = Fernet.generate_key()
KEY = b'9wJjYLOnzrVmta8tQZC3jWZDvVfVyTMLv_4rD2kEjCw='
print("Generated Key:", KEY.decode()) # Replace with your key
cipher = Fernet(KEY)

def decrypt_message(encrypted_msg):
    """Decrypt the message using the pre-shared key."""
    return cipher.decrypt(encrypted_msg).decode()

def handle_packet(packet):
    """Handle incoming ICMP type 47 packets."""
    if packet.haslayer(ICMP) and packet[ICMP].type == 47:
        encrypted_msg = bytes(packet[ICMP].payload)
        try:
            message = decrypt_message(encrypted_msg)
            print(f"Received message: {message}")
        except Exception as e:
            print(f"Error decrypting message: {e}")

def start_server():
    """Start sniffing for ICMP type 47 packets."""
    print("Listening for covert messages...")
    sniff(filter="icmp", prn=handle_packet)

if __name__ == "__main__":
    start_server()