import socket
import threading
from Cryptodome.PublicKey import ECC
from helper_crypto import (
    derive_shared_secret, 
    generate_ecc_keys, 
    encrypt_message_ec_ctr, 
    decrypt_message_ec_ctr, 
    export_public_key
)
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
        self.running = True

    def start_server(self):
        operator_thread = threading.Thread(target=self.listen_operator)
        uav_thread = threading.Thread(target=self.listen_uav)
        operator_thread.start()
        uav_thread.start()
        operator_thread.join()
        uav_thread.join()

    def perform_key_exchange_with_uav(self):
        private_key, public_key = generate_ecc_keys()
        self.uav_socket.sendall(export_public_key(public_key))
        uav_public_key_der = self.uav_socket.recv(1024)
        uav_public_key = ECC.import_key(uav_public_key_der)
        self.uav_session_key = derive_shared_secret(private_key, uav_public_key)
        print("Session key established with UAV.")

    def perform_key_exchange_with_operator(self):
        private_key, public_key = generate_ecc_keys()
        self.operator_socket.sendall(export_public_key(public_key))
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
        while self.running:
            try:
                message = self.operator_socket.recv(1024)
                if not message:
                    print("Operator connection was closed.")
                    self.running = False
                    break
                decrypted_message = decrypt_message_ec_ctr(self.operator_session_key, message)
                if decrypted_message == b"logout":
                    print("Operator has logged out.")
                    self.running = False
                    encrypted_logout = encrypt_message_ec_ctr(self.uav_session_key, b"logout")
                    self.uav_socket.sendall(encrypted_logout)
                    break
                print(f"RA relays message to UAV: {decrypted_message.decode()}")
                encrypted_message = encrypt_message_ec_ctr(self.uav_session_key, decrypted_message)
                self.uav_socket.sendall(encrypted_message)
            except (ConnectionResetError, ConnectionAbortedError):
                print("Operator connection was closed.")
                self.running = False
                break
        self.close_connections()

    def listen_uav(self, host="localhost", port=9998):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(1)
        print("RA is waiting for UAV connection...")
        self.uav_socket, addr = server_socket.accept()
        print("UAV connected.")
        self.perform_key_exchange_with_uav()
        while self.running:
            try:
                message = self.uav_socket.recv(1024)
                if not message:
                    print("UAV connection was closed.")
                    self.running = False
                    break
                decrypted_message = decrypt_message_ec_ctr(self.uav_session_key, message)
                print(f"UAV sends acknowledgment: {decrypted_message.decode()}")
                encrypted_ack = encrypt_message_ec_ctr(self.operator_session_key, decrypted_message)
                self.operator_socket.sendall(encrypted_ack)
            except (ConnectionResetError, ConnectionAbortedError):
                print("UAV connection was closed.")
                self.running = False
                break
        self.close_connections()

    def close_connections(self):
        if self.operator_socket:
            try:
                encrypted_terminate = encrypt_message_ec_ctr(self.operator_session_key, b"session_terminated")
                self.operator_socket.sendall(encrypted_terminate)
            except:
                pass
            self.operator_socket.close()
        if self.uav_socket:
            try:
                encrypted_logout = encrypt_message_ec_ctr(self.uav_session_key, b"logout")
                self.uav_socket.sendall(encrypted_logout)
            except:
                pass
            self.uav_socket.close()
        print("All connections closed.")

if __name__ == "__main__":
    RA = RegistrationAuthority()
    RA.start_server()