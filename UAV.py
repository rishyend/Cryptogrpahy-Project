import socket
from Cryptodome.PublicKey import ECC
from helper_crypto import decrypt_message_ec_ctr, encrypt_message_ec_ctr, generate_ecc_keys, derive_shared_secret

class UAV:
    def __init__(self):
        self.uav_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.session_key_RA = None

    def connect_to_ra(self, host="localhost", port=9998):
        self.uav_socket.connect((host, port))
        print("Connected to RA.")

        self.perform_key_exchange()

    def perform_key_exchange(self):
        private_key, public_key = generate_ecc_keys()

        self.uav_socket.sendall(public_key.export_key(format='DER'))

        ra_public_key_der = self.uav_socket.recv(1024)
        ra_public_key = ECC.import_key(ra_public_key_der)

        self.session_key_RA = derive_shared_secret(private_key, ra_public_key)
        print("Session key established with RA.")

    def receive_mission(self):
        while True:
            message = self.uav_socket.recv(1024)
            if message == b"logout":
                print("Operator has logged out, session closed.")
                break
            decrypted_message = decrypt_message_ec_ctr(self.session_key_RA, message)
            print(f"UAV received mission: {decrypted_message}")

            self.send_ack()

    def send_ack(self):
        ack_message = b"Acknowledgment: Mission received"
        encrypted_ack = encrypt_message_ec_ctr(self.session_key_RA, ack_message)
        self.uav_socket.sendall(encrypted_ack)

if __name__ == "__main__":
    uav = UAV()
    uav.connect_to_ra()
    uav.receive_mission()
