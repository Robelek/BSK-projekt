import os
import tkinter as tk
import psutil
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = None
statusLabel = None
statusPendrive = None
drive = None
pdfPath = None
signButton = None
verifyButton = None



def selectPdf():
    
    global pdfPath

    pdfPath = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
    if pdfPath:
        statusLabel.config(text=f"Selected PDF: {os.path.basename(pdfPath)}", fg="green")
        signButton.config(state=tk.NORMAL)
        verifyButton.config(state=tk.NORMAL)


def signPdf():
    
    global pdfPath

    drive = findKeyFile()

    if not drive:
        messagebox.showerror("Error", "Pendrive not found")
        return None

    pin = getPin()
    if not pin:
        return
    
    privateKey = getPrivateKey(pin)
    if privateKey:
        with open(pdfPath, "rb") as file:
            pdfData = file.read()
        
        signature = privateKey.sign(
            pdfData,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        with open(pdfPath + ".sig", "wb") as sigFile:
            sigFile.write(signature)

        messagebox.showinfo("Success", "PDF Signed Successfully!")
        statusLabel.config(text="Status: PDF Signed", fg="green")


def getPin():
    
    pin = None

    while not pin:
        pin = tk.simpledialog.askinteger("PIN", "Enter your PIN:")
        if not pin:
            if not messagebox.askokcancel("PIN", "PIN cannot be empty. Do you want to try again?"):
                return None
    return pin

def getPrivateKey(pin):

    try:
        with open(drive + "/encryptedPrivateKey.key", "rb") as file:
            iv = file.read(16)
            encryptedPrivateKey = file.read()

        hashObject = hashes.Hash(hashes.SHA256())
        hashObject.update(str(pin).encode())
        encodedKey = hashObject.finalize()

        cipher = Cipher(algorithms.AES(encodedKey), modes.CBC(iv))
        decryptor = cipher.decryptor()

        decryptedPrivateKey = decryptor.update(encryptedPrivateKey) + decryptor.finalize()

        privateKey = serialization.load_pem_private_key(decryptedPrivateKey, password=None)

        return privateKey
    
    except FileNotFoundError:
        messagebox.showerror("Error", "Private key not found on the pendrive")
        return None


def findKeyFile():

    for part in psutil.disk_partitions():
        if "removable" in part.opts:
            drive = part.mountpoint
            for root, dirs, files in os.walk(drive):
                if any(file.endswith(".key") for file in files):
                    statusPendrive.config(text=f"Pendrive status: Pendrive found", fg="green")
                    return drive
                
    statusPendrive.config(text=f"Pendrive status: Pendrive not found", fg="red")
    return None

def verifySignature():

    publicKey = getPublicKey()
    
    if not publicKey:
        return
    
    with open(pdfPath, "rb") as file:
        pdfData = file.read()

    try:
        with open(pdfPath + ".sig", "rb") as sigFile:
            signature = sigFile.read()
        
        publicKey.verify(
            signature,
            pdfData,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        messagebox.showinfo("Success", "Signature is valid!")
        statusLabel.config(text="Status: Signature Verified", fg="green")
    
    except Exception as e:
        messagebox.showerror("Error", "Signature is invalid!")
        statusLabel.config(text="Status: Signature Invalid", fg="red")
    

def getPublicKey():

    publicKeyPath = filedialog.askopenfilename(title="Find Public Key", filetypes=[("Public key files", "*.key")])
    if not publicKeyPath:
        return None
    try:
        
        with open(publicKeyPath, "rb") as file:
            publicKeyBytes = file.read()

        publicKey = serialization.load_pem_public_key(publicKeyBytes)
        return publicKey
    
    except FileNotFoundError:
        messagebox.showerror("Error", "Public key not found!")
        return None
    

def getDrives():
    return [part.mountpoint for part in psutil.disk_partitions() if "removable" in part.opts]


def checkDrivesPeriodically():
    
    global drive
    global previousDrives
    global app

    currentDrives = set(getDrives())

    if currentDrives != previousDrives:
        drive = findKeyFile()
        previousDrives = currentDrives
    
    app.after(2000, checkDrivesPeriodically)
        

app = tk.Tk()

app.title("PAdES PDF Digital Signature")
app.minsize(width=300, height=100)

label = tk.Label(app, text="Select a PDF to Sign or Verify:")
label.pack(pady=10)

selectButton = tk.Button(app, text="Select PDF", command=selectPdf)
selectButton.pack(pady=10)

signButton = tk.Button(app, text="Sign PDF", command=signPdf, state=tk.DISABLED)
signButton.pack(pady=10)

verifyButton = tk.Button(app, text="Verify Signature", command=verifySignature, state=tk.DISABLED)
verifyButton.pack(pady=10)

statusLabel = tk.Label(app, text="Status: Waiting", fg="blue")
statusLabel.pack(pady=10)

statusPendrive = tk.Label(app, text="Pendrive status: Pendrive not found", fg="red")
statusPendrive.pack(pady=10)
drive = findKeyFile()

previousDrives = set(getDrives())
checkDrivesPeriodically()

app.mainloop()