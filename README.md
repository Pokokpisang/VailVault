# VailVault
VeilVault is a secure tool that combines steganography and cryptography to hide sensitive data within images. 

Sure! Here is the complete documentation with the detailed explanations added:

---

# VeilVault Documentation

## Overview

VeilVault is a comprehensive program that provides functionalities for steganography and cryptography. It allows users to securely hide and retrieve sensitive data within images using the Least Significant Bit (LSB) technique and RSA/AES encryption. The program supports embedding and extracting both text and images within other images.

### Key Functionalities
1. **Generate RSA Keys**: Generates RSA public and private keys for encryption and decryption.
2. **Encrypt and Decrypt Data**: Uses AES for data encryption and decryption, secured with RSA for session key encryption.
3. **Embed and Extract Text**: Embeds text within an image using LSB and retrieves it.
4. **Embed and Extract Image**: Embeds an image within another image using LSB and retrieves it.

## Functions

### 1. `generate_keys()`
Generates an RSA key pair (private and public keys). The private key can be encrypted with a passphrase provided by the user.

- **Private Key**: Saved as `private_key.pem`.
- **Public Key**: Saved as `public_key.pem`.

### 2. `encrypt_data(data, public_key)`
Encrypts data using AES with a session key, which is further encrypted using RSA with the provided public key.

- **Session Key**: Randomly generated 256-bit key.
- **Salt**: Randomly generated 128-bit salt.
- **IV**: Randomly generated 128-bit initialization vector.
- **AES**: Uses CBC mode for encryption.
- **RSA**: Encrypts the session key with OAEP padding.

### 3. `decrypt_data(encrypted_session_key, salt, iv, encrypted_data, private_key)`
Decrypts data using AES with the session key decrypted using RSA with the provided private key.

### 4. `pad_data(data)`
Pads data to be a multiple of the AES block size (16 bytes) using PKCS7 padding.

### 5. `unpad_data(padded_data)`
Removes PKCS7 padding from data.

### 6. `compute_seed_from_image_dimensions(image_path)`
Calculates a seed value based on the dimensions (width + height) of the image to ensure consistent pseudorandom behavior.

### 7. `embed_image_in_image(cover_image_path, secret_image_path, output_path, public_key_path)`
Embeds a secret image within a cover image by:
- Encrypting the secret image.
- Embedding the encrypted data into the cover image using LSB.
- Saving the modified cover image as `Hiding_image.png`.

### 8. `extract_image_from_image(image_path, output_file_path, private_key_path)`
Extracts a hidden image from a cover image by:
- Extracting and decrypting the hidden data.
- Saving the secret image.

### 9. `embed_text_in_image(image_path, text, output_path)`
Embeds text within an image by:
- Converting the text to binary.
- Embedding the binary text into the image using LSB.
- Saving the modified image as `text_image.png`.

### 10. `extract_text_from_image(image_path)`
Extracts text hidden within an image by:
- Reading binary data from the image.
- Converting the binary data back to text.
- Saving the extracted text to `decrypt_textFromImage.txt`.

### 11. `main()`
Provides a command-line interface for the user to choose actions and perform operations.

## Algorithms and Techniques

### RSA (Rivest-Shamir-Adleman)
- **Definition:** RSA is an asymmetric encryption algorithm used for secure data transmission.
- **Characteristics:**
  - **Encrypts the Session Key:** The session key is encrypted using the recipient's public RSA key.
  - **OAEP Padding (Optimal Asymmetric Encryption Padding):** Adds randomness to the plaintext before encryption, making the ciphertext more secure against attacks.
  - **Asymmetric Encryption:** Uses a pair of keys (public and private); the public key encrypts data, and the private key decrypts it.
- **Purpose:** RSA securely exchanges the session key used in symmetric encryption. By encrypting the session key with RSA, the sender ensures that only the intended recipient, who possesses the private key, can decrypt it.

### AES (Advanced Encryption Standard)
- **Definition:** AES is a symmetric encryption algorithm widely used for securing data.
- **Characteristics:**
  - **Uses CBC Mode (Cipher Block Chaining):** In CBC mode, each block of plaintext is XORed with the previous ciphertext block before being encrypted.
  - **Benefits of CBC Mode:** Provides strong security by ensuring that identical plaintext blocks produce different ciphertext blocks, provided the IV is different.
  - **Key Size:** AES-256 uses a 256-bit key, providing a very high level of security.
- **Purpose:** AES encrypts data efficiently and securely, making it ideal for use in scenarios requiring fast, reliable encryption of large amounts of data.

### Session Key
- **Definition:** A session key is a single-use symmetric key used for encrypting all messages in a single communication session.
- **Characteristics:**
  - **Randomly Generated:** Ensures each session has a unique key, enhancing security.
  - **256-bit Key:** Provides a high level of security; 256-bit keys are resistant to brute-force attacks.
  - **Symmetric Key:** Used for both encryption and decryption of data within a session.
- **Purpose:** The session key ensures that even if one session's key is compromised, it does not affect the security of other sessions.

### Salt
- **Definition:** A salt is a random value added to the input of a hash function to ensure that the same plaintext does not always produce the same hash.
- **Characteristics:**
  - **Randomly Generated 128-bit Salt:** Ensures high randomness and uniqueness.
  - **128-bit Length:** Sufficient to provide strong security by making precomputed hash attacks (e.g., rainbow tables) infeasible.
- **Purpose:** The salt ensures that even if the same password or session key is used multiple times, the derived encryption key will be different each time, adding an extra layer of security.

### Initialization Vector (IV)
- **Definition:** An IV is a random or pseudo-random value used to initialize the state of a cipher during encryption.
- **Characteristics:**
  - **Randomly Generated 128-bit IV:** Ensures each encryption operation starts with a unique state.
  - **128-bit Length:** Matches the block size of AES, providing strong security.
- **Purpose:** The IV ensures that the same plaintext encrypted with the same key produces different ciphertexts each time, preventing attackers from deducing patterns.

### LSB (Least Significant Bit) Steganography
- **Purpose:** Hide data within images by altering the least significant bits of pixel values.
- **Usage:** Embeds encrypted data within cover images.
- **Pros:**
  - Simple and easy to implement.
  - Minimal visual distortion.
- **Cons:**
  - Vulnerable to image processing attacks.
  - Limited capacity (only a small amount of data can be hidden).

## Why These Components Are Used Together
1. **Security and Performance:**
   - **Symmetric Encryption (AES):** Efficiently encrypts large amounts of data with high performance.
   - **Asymmetric Encryption (RSA):** Securely exchanges the session key, ensuring that only the intended recipient can decrypt it.

2. **Randomness and Unpredictability:**
   - **Session Key, Salt, and IV:** Randomly generated to ensure that each encryption operation is unique and secure, even if the same data and key are used multiple times.

3. **Resistance to Attacks:**
   - **Salt and IV:** Prevent precomputed attacks and ensure different ciphertexts for identical plaintexts.
   - **OAEP Padding:** Enhances the security of RSA encryption by adding randomness.

### Pros and Cons

**Pros:**
- **High Security:** Combines the strengths of symmetric and asymmetric encryption, providing robust security for data transmission and storage.
- **Efficiency:** AES provides fast encryption and decryption, suitable for large data volumes.
- **Unique Encryption:** Random session keys, salts, and IVs ensure that each encryption operation is unique and secure.

**Cons:**
- **Complexity:** Implementing both symmetric and asymmetric encryption requires more computational resources and careful key management.
- **Performance Overhead:** RSA encryption and decryption are computationally intensive, especially for large keys, but this impact is minimized by only encrypting the session key.

## Example Usage

### Generating Keys
```bash
python3 VeilVault.py

Do you want to generate keys, embed text, extract text, embed image, or extract image? generate_keys
Enter a passphrase to encrypt the private key (leave empty for no encryption): [Your Passphrase]
Public and private keys generated and saved as 'public_key.pem' and 'private_key.pem'.
```

### Embedding Text in Image
```bash
python script.py
Do you want to generate keys, embed text, extract text, embed image, or extract image? embed_text
Enter the text you want to embed in the image: [Your Secret Text]
Enter the path to the input image: [Input Image Path]
Enter the path to save the output image (or press Enter to save in the current directory): 
Text has been embedded into the image and saved as text_image.png.
```

### Extracting Text from Image
```bash
python3 VeilVault.py

Do you want to generate keys, embed text, extract text, embed image, or extract image? extract_text
Enter the path to the image with embedded text: [Image Path]
Extracted text: [Your Secret Text]
```
The extracted text is also saved in `decrypt_textFromImage.txt`.

### Embedding Image in Image
```bash
python3 VeilVault.py


Do you want to generate keys, embed text, extract text, embed image, or extract image? embed_image
Enter the path to the cover image: [Cover Image Path]
Enter the path to the secret image: [Secret Image Path]
Enter the path to the public key file: [Public Key Path]
Enter the path to save the output image (or press Enter to save in the current directory): 
The secret image has been embedded into the cover image and saved as Hiding_image.png.
```

### Extracting Image from Image
```bash
python3 VeilVault.py
Do you want to generate keys, embed text, extract text, embed image, or extract image? extract_image
Enter the path to the image with embedded secret image: [Image Path]
Enter the path to the private key file: [Private Key Path]
Enter the path to save the extracted secret image (or press Enter to save in the current directory): 
File extracted to [Output File Path]
```

---

This documentation provides an overview of the code's functionality, detailed explanations of each function, the algorithms used, their pros and cons, and example usage scenarios. VeilVault combines strong encryption and steganography techniques to provide secure data hiding and retrieval within images.
