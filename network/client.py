from scapy.all import IP, ICMP, send
from cryptography.fernet import Fernet
import sys

# Pre-shared symmetric key for encryption
# Generate a random key
# KEY = Fernet.generate_key()
KEY = b'9wJjYLOnzrVmta8tQZC3jWZDvVfVyTMLv_4rD2kEjCw='
print("Generated Key:", KEY.decode())
cipher = Fernet(KEY)

packet = IP(dst="172.17.130.111")/ICMP(type=47)/"test"
send(packet, verbose=False)

def encrypt_message(message):
    """Encrypt the message using the pre-shared key."""
    return cipher.encrypt(message.encode())

def send_covert_message(dest_ip, message):
    """Send an encrypted message in an ICMP type 47 packet."""
    encrypted_msg = encrypt_message(message)
    packet = IP(dst=dest_ip)/ICMP(type=47)/encrypted_msg
    send(packet, verbose=False)
    print(f"Sent encrypted message to {dest_ip}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <destination_ip>")
        sys.exit(1)

    dest_ip = sys.argv[1]
    print("Enter messages to send (Ctrl+C to exit):")
    try:
        while True:
            message = input("> ")
            send_covert_message(dest_ip, message)
    except KeyboardInterrupt:
        print("\nExiting...")