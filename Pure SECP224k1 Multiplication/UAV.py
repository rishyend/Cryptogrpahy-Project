import socket
from Cryptodome.PublicKey import ECC
from helper_crypto import (
    decrypt_message_ec_ctr, 
    encrypt_message_ec_ctr, 
    generate_ecc_keys, 
    derive_shared_secret, 
    export_public_key
)

class UAV:
    def __init__(self):
        self.uav_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.session_key_RA = None
        self.running = True

    def connect_to_ra(self, host="localhost", port=9998):
        try:
            self.uav_socket.connect((host, port))
            print("Connected to RA.")
            self.perform_key_exchange()
        except ConnectionRefusedError:
            print("Failed to connect to RA. Make sure RA is running.")
            self.running = False

    def perform_key_exchange(self):
        private_key, public_key = generate_ecc_keys()
        self.uav_socket.sendall(export_public_key(public_key))
        ra_public_key_der = self.uav_socket.recv(1024)
        ra_public_key = ECC.import_key(ra_public_key_der)
        self.session_key_RA = derive_shared_secret(private_key, ra_public_key)
        print("Session key established with RA.")

    def receive_mission(self):
        while self.running:
            try:
                message = self.uav_socket.recv(1024)
                if not message:
                    print("Connection to RA closed.")
                    self.running = False
                    break
                decrypted_message = decrypt_message_ec_ctr(self.session_key_RA, message)
                if decrypted_message == b"logout":
                    print("Operator has logged out, session closed.")
                    self.running = False
                    break
                print(f"UAV received mission: {decrypted_message.decode()}")
                self.send_ack()
            except (ConnectionResetError, ConnectionAbortedError):
                print("Connection to RA was forcibly closed.")
                self.running = False
                break
        self.uav_socket.close()
        print("UAV session ended.")

    def send_ack(self):
        try:
            ack_message = b"Acknowledgment: Mission received"
            encrypted_ack = encrypt_message_ec_ctr(self.session_key_RA, ack_message)
            self.uav_socket.sendall(encrypted_ack)
        except (ConnectionResetError, ConnectionAbortedError):
            print("Failed to send acknowledgment. Connection to RA was closed.")
            self.running = False

if __name__ == "__main__":
    uav = UAV()
    uav.connect_to_ra()
    if uav.running:
        uav.receive_mission()
