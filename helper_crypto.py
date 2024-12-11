import os
import struct
from Cryptodome.PublicKey import ECC
from Cryptodome.Math.Numbers import Integer
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Hash import SHA256


def generate_ecc_keys():
    private_key = ECC.generate(curve="P-256")
    public_key = private_key.public_key()
    return private_key, public_key


def derive_shared_secret(private_key, peer_public_key):
    shared_secret_point = peer_public_key.pointQ * private_key.d
    shared_secret = Integer(shared_secret_point.x).to_bytes()
    session_key = HKDF(
        master=shared_secret, key_len=32, salt=None, hashmod=SHA256
    )
    return session_key



# AES S-Box
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

# AES Rcon values
RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F,
    0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4,
    0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91
]



def sub_bytes(state):
    """
    S-Box substitution to the AES state.
    """
    for i in range(4):
        for j in range(4):
            state[i][j] = SBOX[state[i][j]]
    return state


def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]
    return state


def mix_columns(state):
    def xtime(a):
        return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1

    for i in range(4):
        t = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3]
        u = state[i][0]
        state[i][0] ^= t ^ xtime(state[i][0] ^ state[i][1])
        state[i][1] ^= t ^ xtime(state[i][1] ^ state[i][2])
        state[i][2] ^= t ^ xtime(state[i][2] ^ state[i][3])
        state[i][3] ^= t ^ xtime(state[i][3] ^ u)
    return state


def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state


def key_expansion(key):
    pass


def aes_encrypt_block(plain_block, key):
    state = [[plain_block[row * 4 + col] for col in range(4)] for row in range(4)]
    round_keys = key_expansion(key)

    state = add_round_key(state, round_keys[0])

    for round_num in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_num])

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])

    return bytes(sum(state, []))


def increment_counter(counter):
    return (int.from_bytes(counter, "big") + 1).to_bytes(16, "big")


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def key_expansion(key):
    key_size = 16  
    rounds = 10 
    key_columns = 4  
    round_keys = []

    # Initializing round keys with the original key
    round_keys.append([[key[i * 4 + j] for j in range(4)] for i in range(4)])

    for i in range(1, rounds + 1):
        prev_round_key = round_keys[-1]
        next_round_key = []

        t = prev_round_key[3][:] 
        t = t[1:] + t[:1]  # Rotate the column
        t = [SBOX[b & 0xFF] for b in t]  # Apply S-box substitution with masking
        t[0] ^= RCON[i]  # XOR the first byte with the round constant
        next_round_key.append([t[j] ^ prev_round_key[0][j] for j in range(4)])

        # Generating remaining columns
        for j in range(1, key_columns):
            t = [next_round_key[j - 1][k] ^ prev_round_key[j][k] for k in range(4)]
            next_round_key.append(t)

        round_keys.append(next_round_key)

    return round_keys


def encrypt_message_ec_ctr(key, message):
    key = key[:16] 
    nonce = os.urandom(8) 
    counter = nonce + b'\x00' * 8 

    ciphertext = b""
    for i in range(0, len(message), 16):
        encrypted_counter = aes_encrypt_block(counter, key)
        plaintext_block = message[i:i + 16]
        ciphertext_block = xor_bytes(plaintext_block, encrypted_counter[:len(plaintext_block)])
        ciphertext += ciphertext_block
        counter = increment_counter(counter)

    return nonce + ciphertext


def decrypt_message_ec_ctr(key, encrypted_message):
    key = key[:16] 
    nonce = encrypted_message[:8]
    ciphertext = encrypted_message[8:]
    counter = nonce + b'\x00' * 8

    plaintext = b""
    for i in range(0, len(ciphertext), 16):
        encrypted_counter = aes_encrypt_block(counter, key)
        ciphertext_block = ciphertext[i:i + 16]
        plaintext_block = xor_bytes(ciphertext_block, encrypted_counter[:len(ciphertext_block)])
        plaintext += plaintext_block
        counter = increment_counter(counter)

    return plaintext
