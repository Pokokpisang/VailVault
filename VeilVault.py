from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from PIL import Image
import numpy as np
import os
import random
import zlib
from getpass import getpass

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    passphrase = getpass("Enter a passphrase to encrypt the private key (leave empty for no encryption): ")
    if passphrase:
        encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        encryption_algorithm = serialization.NoEncryption()

    with open("private_key.pem", "wb") as private_key_file:
        private_key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        ))

    public_key = private_key.public_key()
    with open("public_key.pem", "wb") as public_key_file:
        public_key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("Public and private keys generated and saved as 'public_key.pem' and 'private_key.pem'.")

def encrypt_data(data, public_key):
    session_key = os.urandom(32)  # 32 bytes for 256-bit key
    salt = os.urandom(16)  # 16 bytes for 128-bit salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend()
    )
    key = kdf.derive(session_key)
    iv = os.urandom(16)  # 16 bytes for 128-bit IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad_data(data)
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    encrypted_session_key = public_key.encrypt(
        session_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_session_key, salt, iv, encrypted_data

def pad_data(data):
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def unpad_data(padded_data):
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def decrypt_data(encrypted_session_key, salt, iv, encrypted_data, private_key):
    try:
        session_key = private_key.decrypt(
            encrypted_session_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200000,
            backend=default_backend()
        )
        key = kdf.derive(session_key)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        decrypted_data = unpad_data(decrypted_padded_data)
        return decrypted_data
    except Exception as e:
        print(f"Decryption failed: {e}")
        raise

def compute_seed_from_image_dimensions(image_path):
    with Image.open(image_path) as img:
        width, height = img.size
    return width + height

def embed_image_in_image(cover_image_path, secret_image_path, output_path, public_key_path):
    try:
        cover_img = Image.open(cover_image_path)
        cover_img = cover_img.convert("RGBA")
        cover_pixels = np.array(cover_img)
        
        with open(public_key_path, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        seed = compute_seed_from_image_dimensions(cover_image_path)
        prng = random.Random(seed)
        
        with open(secret_image_path, 'rb') as f:
            file_bytes = f.read()
        
        compressed_data = zlib.compress(file_bytes)
        encrypted_session_key, salt, iv, encrypted_data = encrypt_data(compressed_data, public_key)
        
        filename = os.path.basename(secret_image_path).encode()
        filename_size = len(filename)

        data_to_encode = (filename_size.to_bytes(4, 'big') + filename +
                          encrypted_session_key + salt + iv + encrypted_data)
        
        file_size = len(data_to_encode)
        num_pixels_required = file_size * 8
        if num_pixels_required > cover_pixels.size // 4:
            raise ValueError("Image is not large enough to hide the file.")
        
        pixel_indices = list(range(cover_pixels.size // 4))
        prng.shuffle(pixel_indices)
        
        for i in range(64):
            idx = pixel_indices[i]
            bit = (file_size >> (63 - i)) & 0x1
            if (cover_pixels[idx // cover_pixels.shape[1], idx % cover_pixels.shape[1], 0] & 0x1) != bit:
                cover_pixels[idx // cover_pixels.shape[1], idx % cover_pixels.shape[1], 0] ^= 0x1
        
        for i, byte in enumerate(data_to_encode):
            for bit in range(8):
                idx = pixel_indices[64 + i * 8 + bit]
                if (cover_pixels[idx // cover_pixels.shape[1], idx % cover_pixels.shape[1], 0] & 0x1) != ((byte >> (7 - bit)) & 0x1):
                    cover_pixels[idx // cover_pixels.shape[1], idx % cover_pixels.shape[1], 0] ^= 0x1
        
        new_img = Image.fromarray(cover_pixels, 'RGBA')
        new_img.save(output_path, format='PNG', optimize=True)
        print(f"File '{secret_image_path}' has been successfully hidden in '{output_path}'.")
    except Exception as e:
        print(f"An error occurred during embedding image into image: {e}")

def extract_image_from_image(image_path, output_file_path, private_key_path):
    try:
        passphrase = getpass("Enter the private key passphrase (leave empty if no passphrase): ")
        with open(private_key_path, 'rb') as key_file:
            if passphrase:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=passphrase.encode(),
                    backend=default_backend()
                )
            else:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
        
        encrypted_session_key_size = private_key.key_size // 8
        seed = compute_seed_from_image_dimensions(image_path)
        prng = random.Random(seed)

        img = Image.open(image_path)
        img = img.convert('RGBA')
        pixels = np.array(img)
        flat_pixels = pixels.flatten()
        
        channel_multiplier = 4

        file_size = 0
        for i in range(64):
            file_size = (file_size << 1) | (flat_pixels[i * channel_multiplier] & 0x1)
        
        num_bytes_to_extract = file_size
        extracted_bytes = []
        
        pixel_indices = list(range(pixels.size // 4))
        prng.shuffle(pixel_indices)
        
        for i in range(64):
            idx = pixel_indices[i]
            file_size = (file_size << 1) | (pixels[idx // pixels.shape[1], idx % pixels.shape[1], 0] & 0x1)
        
        num_bytes_to_extract = file_size
        extracted_bytes = []
        for i in range(num_bytes_to_extract):
            byte = 0
            for bit in range(8):
                idx = pixel_indices[64 + i * 8 + bit]
                byte = (byte << 1) | (pixels[idx // pixels.shape[1], idx % pixels.shape[1], 0] & 0x1)
            extracted_bytes.append(byte)
        
        data_to_decode = bytes(extracted_bytes)

        filename_size = int.from_bytes(data_to_decode[:4], 'big')
        filename = data_to_decode[4:4 + filename_size].decode()
        
        offset = 4 + filename_size
        encrypted_session_key = data_to_decode[offset:offset + encrypted_session_key_size]
        salt = data_to_decode[offset + encrypted_session_key_size:offset + encrypted_session_key_size + 16]
        iv = data_to_decode[offset + encrypted_session_key_size + 16:offset + encrypted_session_key_size + 32]
        encrypted_data = data_to_decode[offset + encrypted_session_key_size + 32:]
        
        decrypted_data = decrypt_data(encrypted_session_key, salt, iv, encrypted_data, private_key)
        decompressed_data = zlib.decompress(decrypted_data)
        
        if not output_file_path:
            output_file_path = os.path.join(os.getcwd(), filename)
        
        with open(output_file_path, 'wb') as f:
            f.write(decompressed_data)

        print(f"File extracted to {output_file_path}")
    except Exception as e:
        print(f"An error occurred during extracting image from image: {e}")

def embed_text_in_image(image_path, text, output_path):
    try:
        img = Image.open(image_path)
        img = img.convert("RGB")
        pixels = np.array(img)

        # Convert text to binary
        binary_text = ''.join(format(ord(char), '08b') for char in text)
        text_length = len(binary_text)

        if text_length > pixels.size * 3:
            raise ValueError("The image is too small to hold the text.")

        # Add delimiter to mark the end of text
        binary_text += '00000000' * 4  # Four null characters to indicate the end

        # Embed binary text into the image
        idx = 0
        for i in range(pixels.shape[0]):
            for j in range(pixels.shape[1]):
                for k in range(3):
                    if idx < len(binary_text):
                        pixel_bin = format(pixels[i, j, k], '08b')
                        pixel_bin = pixel_bin[:-1] + binary_text[idx]
                        pixels[i, j, k] = int(pixel_bin, 2)
                        idx += 1

        modified_image = Image.fromarray(pixels)
        modified_image.save(output_path)
        print(f"Text has been embedded into the image and saved as {output_path}.")
    except Exception as e:
        print(f"An error occurred during embedding text into image: {e}")

def extract_text_from_image(image_path):
    try:
        img = Image.open(image_path)
        img = img.convert("RGB")
        pixels = np.array(img)

        binary_text = ''
        for i in range(pixels.shape[0]):
            for j in range(pixels.shape[1]):
                for k in range(3):
                    binary_text += bin(pixels[i, j, k])[-1]

        # Split the binary text into 8-bit chunks
        binary_chars = [binary_text[i:i + 8] for i in range(0, len(binary_text), 8)]

        # Convert binary chunks to text
        extracted_text = ''
        for binary_char in binary_chars:
            char = chr(int(binary_char, 2))
            if char == '\x00':
                break  # Stop at the delimiter
            extracted_text += char

        # Save the extracted text to a file
        with open("decrypt_textFromImage.txt", "w") as text_file:
            text_file.write(extracted_text)

        return extracted_text
    except Exception as e:
        print(f"An error occurred during extracting text from image: {e}")

def main():
    while True:
        try:
            action = input("Do you want to generate keys, embed text, extract text, embed image, or extract image? (generate_keys/embed_text/extract_text/embed_image/extract_image): ").strip().lower()

            if action == 'generate_keys':
                generate_keys()

            elif action == 'embed_text':
                text = input("Enter the text you want to embed in the image: ")

                image_path = input("Enter the path to the input image: ")
                output_path = input("Enter the path to save the output image (or press Enter to save in the current directory): ")
                if not output_path:
                    output_path = os.path.join(os.getcwd(), "text_image.png")
                elif not os.path.isabs(output_path):
                    output_path = os.path.join(os.getcwd(), output_path)

                embed_text_in_image(image_path, text, output_path)

            elif action == 'extract_text':
                image_path = input("Enter the path to the image with embedded text: ")

                extracted_text = extract_text_from_image(image_path)
                print(f"Extracted text: {extracted_text}")

            elif action == 'embed_image':
                cover_image_path = input("Enter the path to the cover image: ")
                secret_image_path = input("Enter the path to the secret image: ")
                public_key_path = input("Enter the path to the public key file: ")

                output_path = input("Enter the path to save the output image (or press Enter to save in the current directory): ")
                if not output_path:
                    output_path = os.path.join(os.getcwd(), "Hiding_image.png")
                elif not os.path.isabs(output_path):
                    output_path = os.path.join(os.getcwd(), output_path)

                try:
                    embed_image_in_image(cover_image_path, secret_image_path, output_path, public_key_path)
                    print(f"The secret image has been embedded into the cover image and saved as {output_path}.")
                except ValueError as e:
                    print(f"Error: {e}")
                    print("Please use a larger cover image or a smaller secret image.")

            elif action == 'extract_image':
                image_path = input("Enter the path to the image with embedded secret image: ")
                private_key_path = input("Enter the path to the private key file: ")

                output_path = input("Enter the path to save the extracted secret image (or press Enter to save in the current directory): ")
                if not output_path:
                    output_path = os.path.join(os.getcwd(), "extracted_secret_image")

                extract_image_from_image(image_path, output_path, private_key_path)

            else:
                print("Invalid action. Please enter 'generate_keys', 'embed_text', 'extract_text', 'embed_image', or 'extract_image'.")

        except FileNotFoundError as e:
            print(f"File not found: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")

        cont = input("Do you want to perform another operation? (yes/no): ").strip().lower()
        if cont != 'yes':
            break

if __name__ == "__main__":
    main()
