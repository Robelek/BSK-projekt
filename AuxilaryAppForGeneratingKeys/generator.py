import os
import tkinter as tk
from tkinter import messagebox
from tkinter import END

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generateKeys():
    privateKey = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    publicKey = privateKey.public_key()

    return privateKey, publicKey

def generateAndSaveKeys():
    try:
        pin = int(pinEntry.get())

    except ValueError:
        tk.messagebox.showerror("Błąd", "Wprowadzono PIN niebędący liczbą")
        pinEntry.delete(0, END)
        return

    privateKey, publicKey = generateKeys()
    privateKeyBytes = privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    publicKeyBytes = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    hashObject = hashes.Hash(hashes.SHA256())
    hashObject.update(str(pin).encode())

    encodedKey = hashObject.finalize()
    #print(encodedKey.hex())

    #useful source: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(encodedKey), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padderObject = padding.PKCS7(256).padder()
    paddedData = padderObject.update(privateKeyBytes) + padderObject.finalize()

    encryptedPrivateKey = encryptor.update(paddedData) + encryptor.finalize()

    try:
        with open("encryptedPrivateKey.key", "wb") as file:
            file.write(iv)
            file.write(encryptedPrivateKey)

        with open("public.key", "wb") as file:
            file.write(publicKeyBytes)

        tk.messagebox.showinfo("Sukces", "Klucze zostały zapisane do folderu tej aplikacji")

    except:
        tk.messagebox.showerror("Błąd", "Aplikacja napotkała błąd przy zapisywaniu kluczy")






appRoot = tk.Tk()
appRoot.title("Generator kluczy RSA")
appRoot.minsize(width=300, height=100)

textLabel = tk.Label(appRoot, text="Wprowadź pin (w postaci liczby):", font=("Arial", 12))
textLabel.pack(pady=10)

pinEntry = tk.Entry(appRoot, width=15)
pinEntry.pack(pady=10)

generateButton = tk.Button(appRoot, text="GENERUJ KLUCZE", command=generateAndSaveKeys)
generateButton.pack(pady=10)



appRoot.mainloop()

