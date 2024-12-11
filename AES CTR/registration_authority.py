import socket
import threading
from Cryptodome.PublicKey import ECC
from helper_crypto import derive_shared_secret, generate_ecc_keys, encrypt_message_ec_ctr, decrypt_message_ec_ctr
from Cryptodome.Random import get_random_bytes

class RegistrationAuthority:
    def __init__(self):
        self.operator_socket = None
        self.uav_socket = None
        self.operator_session_key = None
        self.uav_session_key = None

        self.valid_credentials = {
            b"user1": b"pass123"
        }

    def start_server(self):
        operator_thread = threading.Thread(target=self.listen_operator)
        uav_thread = threading.Thread(target=self.listen_uav)

        operator_thread.start()
        uav_thread.start()

        operator_thread.join()
        uav_thread.join()

    def perform_key_exchange_with_uav(self):
        private_key, public_key = generate_ecc_keys()

        self.uav_socket.sendall(public_key.export_key(format='DER'))

        uav_public_key_der = self.uav_socket.recv(1024)
        uav_public_key = ECC.import_key(uav_public_key_der)

        self.uav_session_key = derive_shared_secret(private_key, uav_public_key)
        print("Session key established with UAV.")

    def perform_key_exchange_with_operator(self):
        private_key, public_key = generate_ecc_keys()

        self.operator_socket.sendall(public_key.export_key(format='DER'))

        operator_public_key_der = self.operator_socket.recv(1024)
        operator_public_key = ECC.import_key(operator_public_key_der)

        self.operator_session_key = derive_shared_secret(private_key, operator_public_key)
        print("Session key established with Operator.")

    def listen_operator(self, host="localhost", port=9999):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(1)
        print("RA is waiting for Operator connection...")

        self.operator_socket, addr = server_socket.accept()
        print("Operator connected.")

        credentials = self.operator_socket.recv(1024)
        operator_id, operator_pw = credentials.split(b" ")

        if operator_id in self.valid_credentials and self.valid_credentials[operator_id] == operator_pw:
            print(f"Operator {operator_id.decode()} authenticated successfully.")
            self.operator_socket.sendall(b"Authentication successful")
        else:
            print(f"Operator {operator_id.decode()} failed to authenticate.")
            self.operator_socket.sendall(b"Authentication failed")
            self.operator_socket.close()
            return  

        self.perform_key_exchange_with_operator()

        while True:
            message = self.operator_socket.recv(1024)
            if message == b"logout":
                print("Operator has logged out.")
                break

            decrypted_message = decrypt_message_ec_ctr(self.operator_session_key, message)
            print(f"RA relays message to UAV: {decrypted_message}")

            # Relay to UAV
            encrypted_message = encrypt_message_ec_ctr(self.uav_session_key, decrypted_message)
            self.uav_socket.sendall(encrypted_message)

    def listen_uav(self, host="localhost", port=9998):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(1)
        print("RA is waiting for UAV connection...")

        self.uav_socket, addr = server_socket.accept()
        print("UAV connected.")

        self.perform_key_exchange_with_uav()

        while True:
            message = self.uav_socket.recv(1024)
            decrypted_message = decrypt_message_ec_ctr(self.uav_session_key, message)
            print(f"UAV sends acknowledgment: {decrypted_message}")

            # Relay back to Operator
            encrypted_ack = encrypt_message_ec_ctr(self.operator_session_key, decrypted_message)
            self.operator_socket.sendall(encrypted_ack)

if __name__ == "__main__":
    RA = RegistrationAuthority()
    RA.start_server()
