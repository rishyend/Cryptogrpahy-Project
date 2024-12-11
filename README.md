# **Implementation of Secure Communication Between UAV and Operator**

Two parties, **UAV (Unmanned Aerial Vehicle)** and **Operator**, communicate through a middleman called **Registration Authority (RA)** using **TCP SOCK_STREAM connections**.

The implementation is carried out using three different methods:

1. **AES CTR** (implemented from scratch without hardware acceleration).  
2. **Pure scalar multiplications** on the **SECP224k1 curve** and **BLAKE3 hash function**.  
3. **Partial scalar multiplication** + **ChaCha20-Poly1305 combined encryption and decryption**.

---

## **Block Diagram Representations**

![mermaid-flow](https://github.com/user-attachments/assets/fb546766-da76-4f24-825f-cad3cf1845a6)

![pure secp](https://github.com/user-attachments/assets/a5523bce-20dc-4d74-8818-02894abbb213)

![chacha + ecc](https://github.com/user-attachments/assets/7324754e-beee-4652-869f-6783b725aa90)

---

## **Results of Implementation**

### Socket Communication Terminals:

#### Registration Authority (RA) Terminal:
![RA](https://github.com/user-attachments/assets/61296cf8-5306-4b5c-8ed0-b4e17832bbf9)

#### Operator Terminal:
![OP](https://github.com/user-attachments/assets/2edd0e7e-556d-40bf-9ecc-285c912f4325)

#### UAV Terminal:
![UAV](https://github.com/user-attachments/assets/296d5ee1-4226-41d3-8203-4064fa408f03)

---

## **Comparison Results**

All methods are compared in terms of **Entropy (Randomness)** in Ciphertext and **Execution Time**. The results are as follows:

![comp](https://github.com/user-attachments/assets/2a003234-32b4-420f-a1a9-c977b11c9947)

---

## **Required Libraries**

> **Note:** The `fastecdsa` library does not work on Windows.

```bash
pip install blake3
pip install pycryptodome
pip install pycryptodomex
pip install fastecdsa
