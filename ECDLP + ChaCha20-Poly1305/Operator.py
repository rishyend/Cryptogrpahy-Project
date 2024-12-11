import socket
import threading
from Cryptodome.PublicKey import ECC
from helper_crypto import (
    encrypt_message_ec_ctr, 
    decrypt_message_ec_ctr, 
    generate_ecc_keys, 
    derive_shared_secret, 
    export_public_key
)

class Operator:
    def __init__(self):
        self.operator_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.session_key_RA = None

    def connect_to_ra(self, host="localhost", port=9999):
        self.operator_socket.connect((host, port))
        print("Connected to RA.")

    def authenticate(self):
        self.IDOP = input("Enter Operator ID: ").encode()
        self.PWOP = input("Enter Password: ").encode()
        self.operator_socket.sendall(self.IDOP + b" " + self.PWOP)
        auth_response = self.operator_socket.recv(1024)
        if auth_response == b"Authentication successful":
            print("Authentication successful.")
        else:
            print("Authentication failed.")
            self.operator_socket.close()
            return False
        self.perform_key_exchange()
        return True

    def perform_key_exchange(self):
        private_key, public_key = generate_ecc_keys()
        self.operator_socket.sendall(export_public_key(public_key))
        ra_public_key_der = self.operator_socket.recv(1024)
        ra_public_key = ECC.import_key(ra_public_key_der)
        self.session_key_RA = derive_shared_secret(private_key, ra_public_key)
        print("Session key established with RA.")

    def send_mission(self):
        while True:
            mission = input("Enter mission for UAV (type 'logout' to end): ")
            if mission.lower() == "logout":
                encrypted_logout = encrypt_message_ec_ctr(self.session_key_RA, b"logout")
                self.operator_socket.sendall(encrypted_logout)
                print("Logged out and session closed.")
                break
            else:
                encrypted_message = encrypt_message_ec_ctr(self.session_key_RA, mission.encode())
                self.operator_socket.sendall(encrypted_message)

    def receive_ack(self):
        while True:
            try:
                ack_message = self.operator_socket.recv(1024)
                if not ack_message:
                    print("Connection closed by RA.")
                    break
                decrypted_ack = decrypt_message_ec_ctr(self.session_key_RA, ack_message)
                if decrypted_ack == b"session_terminated":
                    print("Session terminated by RA.")
                    break
                print(f"Operator received acknowledgment from UAV: {decrypted_ack.decode()}")
            except ConnectionResetError:
                print("Connection reset by RA.")
                break

if __name__ == "__main__":
    operator = Operator()
    operator.connect_to_ra()
    if operator.authenticate():
        ack_thread = threading.Thread(target=operator.receive_ack)
        ack_thread.start()
        operator.send_mission()
        ack_thread.join()