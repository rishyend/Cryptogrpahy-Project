import os
from fastecdsa import keys, curve
from fastecdsa.point import Point
from blake3 import blake3
from Cryptodome.PublicKey import ECC
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


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def generate_full_keystream(shared_secret, length):
    scalar = int.from_bytes(shared_secret, "big")
    base_point = curve.secp224k1.G

    keystream = []
    current_point = montgomery_ladder(base_point, scalar, curve.secp224k1)
    keystream.extend(int(current_point.x).to_bytes(28, "big"))

    while len(keystream) < length:
        scalar = int.from_bytes(blake3(scalar.to_bytes(28, "big")).digest()[:28], "big") % curve.secp224k1.q
        current_point = montgomery_ladder(base_point, scalar, curve.secp224k1)
        keystream.extend(int(current_point.x).to_bytes(28, "big"))

    # Trim to the required length
    return bytes(keystream[:length])



def process_message_ec_ctr(shared_secret, input_data, is_encrypt=True):
    nonce = input_data[:12]
    remaining_data = input_data[12:]

    keystream = generate_full_keystream(blake3(shared_secret).digest()[:28], len(remaining_data))

    if is_encrypt:
        ciphertext = xor_bytes(remaining_data, keystream)
        return nonce + ciphertext
    else:
        plaintext = xor_bytes(remaining_data, keystream)
        return plaintext


def encrypt_message_ec_ctr(shared_secret, plaintext):
    nonce = os.urandom(12)
    return process_message_ec_ctr(shared_secret, nonce + plaintext, is_encrypt=True)


def decrypt_message_ec_ctr(shared_secret, ciphertext):
    return process_message_ec_ctr(shared_secret, ciphertext, is_encrypt=False)


if __name__ == "__main__":
    private_key, public_key = generate_ecc_keys()
    peer_private_key, peer_public_key = generate_ecc_keys()

    shared_secret = derive_shared_secret(private_key, peer_public_key)

    plaintext = b"Hello, SECP224k1 encryption!" * 40  # Ensure it spans multiple blocks
    ciphertext = encrypt_message_ec_ctr(shared_secret, plaintext)
    decrypted = decrypt_message_ec_ctr(shared_secret, ciphertext)

    print(f"Original: {plaintext}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted: {decrypted}")
    print(f"Decryption Successful: {plaintext == decrypted}")
