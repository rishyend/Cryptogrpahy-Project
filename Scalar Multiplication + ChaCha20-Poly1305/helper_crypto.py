import os
from fastecdsa import keys, curve
from fastecdsa.point import Point
from blake3 import blake3
from Cryptodome.PublicKey import ECC
from Cryptodome.Cipher import ChaCha20_Poly1305
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA256


def montgomery_ladder(point, scalar, curve):
    r0 = curve.G * 0  # Identity element
    r1 = point
    scalar_bits = bin(scalar)[2:]
    for bit in scalar_bits:
        if bit == "0":
            r1 = r0 + r1
            r0 = r0 + r0
        else:
            r0 = r0 + r1
            r1 = r1 + r1
    return r0


def export_public_key(public_key):
    return public_key.export_key(format="DER")

def generate_ecc_keys():
    private_key = ECC.generate(curve="P-256")
    public_key = private_key.public_key()
    return private_key, public_key


def derive_shared_secret(private_key, peer_public_key):
    shared_secret_point = peer_public_key.pointQ * private_key.d
    shared_secret = int(shared_secret_point.x).to_bytes(32, 'big')
    return shared_secret


def ecc_keystream(base_key):
    scalar = int.from_bytes(base_key, "big")
    base_point = curve.secp224k1.G
    result_point = montgomery_ladder(base_point, scalar, curve.secp224k1)
    x_coord = result_point.x
    return int(x_coord).to_bytes(28, "big")


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def process_message_ec_ctr(shared_secret, input_data, is_encrypt=True):
    nonce = input_data[:12]
    remaining_data = input_data[12:]
    ecc_key = ecc_keystream(blake3(shared_secret).digest()[:28])
    derived_key = HKDF(master=shared_secret, key_len=32, salt=b"", hashmod=SHA256, num_keys=1)

    if len(remaining_data) <= 28:  # Adjusted for 224 bits
        if is_encrypt:
            encrypted_data = xor_bytes(remaining_data, ecc_key[:len(remaining_data)])
            return nonce + encrypted_data
        else:
            decrypted_data = xor_bytes(remaining_data, ecc_key[:len(remaining_data)])
            return decrypted_data
    else:
        part_a, part_b = remaining_data[:28], remaining_data[28:]
        if is_encrypt:
            encrypted_part_a = xor_bytes(part_a, ecc_key)
            cipher = ChaCha20_Poly1305.new(key=derived_key, nonce=nonce)
            encrypted_part_b, tag = cipher.encrypt_and_digest(part_b)
            return nonce + encrypted_part_a + encrypted_part_b + tag
        else:
            encrypted_part_a, encrypted_part_b, tag = remaining_data[:28], remaining_data[28:-16], remaining_data[-16:]
            decrypted_part_a = xor_bytes(encrypted_part_a, ecc_key)
            cipher = ChaCha20_Poly1305.new(key=derived_key, nonce=nonce)
            decrypted_part_b = cipher.decrypt_and_verify(encrypted_part_b, tag)
            return decrypted_part_a + decrypted_part_b


def encrypt_message_ec_ctr(shared_secret, plaintext):
    nonce = os.urandom(12)
    return process_message_ec_ctr(shared_secret, nonce + plaintext, is_encrypt=True)


def decrypt_message_ec_ctr(shared_secret, ciphertext):
    return process_message_ec_ctr(shared_secret, ciphertext, is_encrypt=False)
