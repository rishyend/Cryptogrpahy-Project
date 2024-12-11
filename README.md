Two Parties -  UAV(Unmanned Aerial Vehicle) and Operator communicate through a middleman called Registration Authority(RA) (TCP SOCK_STREAM connections) ;

Implemented using three different methods:

1. Using AES CTR that is implemented from scratch without hardware acceleration
2. Using Pure scalar multiplications on SECP224k1 curve and BLAKE3 hash function.
3. Using Partial scalar multiplication + ChaCha20-Poly1305 combined encryption and decryption.

# IMPLEMENTATION BLOCK DIAGRAM REPRESENTATIONS

![mermaid-flow](https://github.com/user-attachments/assets/fb546766-da76-4f24-825f-cad3cf1845a6)

![pure secp](https://github.com/user-attachments/assets/a5523bce-20dc-4d74-8818-02894abbb213)

![chacha + ecc ](https://github.com/user-attachments/assets/7324754e-beee-4652-869f-6783b725aa90)

# RESULTS OF IMPLEMENTATION 
  done through Socket Communication:

Registration Authority Terminal:

![RA](https://github.com/user-attachments/assets/61296cf8-5306-4b5c-8ed0-b4e17832bbf9)

Operator Terminal:

![OP](https://github.com/user-attachments/assets/2edd0e7e-556d-40bf-9ecc-285c912f4325)

UAV Terminal:

![UAV](https://github.com/user-attachments/assets/296d5ee1-4226-41d3-8203-4064fa408f03)



### Required Libraries (fastecdsa doesn't work in Windows):

```bash
pip install blake3
pip install pycryptodome
pip install pycryptodomex
pip install fastecdsa
pip install


# COMPARISION RESULTS
All the methods are compared in terms of Entropy(Randomness) in Ciphertext and Execution time with the results below:

![comp](https://github.com/user-attachments/assets/2a003234-32b4-420f-a1a9-c977b11c9947)

