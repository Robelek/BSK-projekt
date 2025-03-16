import os
import tkinter as tk
import psutil
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class PAdESApp:

    def __init__(self, app):
        self.app = app
        self.app.title("PAdES PDF Digital Signature")
        app.minsize(width=300, height=100)

        self.label = tk.Label(app, text="Select a PDF to Sign or Verify:")
        self.label.pack(pady=10)

        self.selectButton = tk.Button(app, text="Select PDF", command=self.selectPdf)
        self.selectButton.pack(pady=10)

        self.signButton = tk.Button(app, text="Sign PDF", command=self.signPdf, state=tk.DISABLED)
        self.signButton.pack(pady=10)

        self.verifyButton = tk.Button(app, text="Verify Signature", command=self.verifySignature, state=tk.DISABLED)
        self.verifyButton.pack(pady=10)

        self.statusLabel = tk.Label(app, text="Status: Waiting", fg="blue")
        self.statusLabel.pack(pady=10)

        self. statusPendrive = tk.Label(app, text="Pendrive status: Pendrive not found", fg="red")
        self.statusPendrive.pack(pady=10)
        self.drive = self.findKeyFile()

        self.pdfPath = None
        self.previousDrives = set(self.getDrives())
        self.checkDrivesPeriodically()


    def getDrives(self):
        return [part.mountpoint for part in psutil.disk_partitions() if "removable" in part.opts]


    def checkDrivesPeriodically(self):
        currentDrives = set(self.getDrives())
        if currentDrives != self.previousDrives:
            self.drive = self.findKeyFile()
            self.previousDrives = currentDrives
        
        self.app.after(2000, self.checkDrivesPeriodically)



    def selectPdf(self):
        self.pdfPath = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        if self.pdfPath:
            self.statusLabel.config(text=f"Selected PDF: {os.path.basename(self.pdfPath)}", fg="green")
            self.signButton.config(state=tk.NORMAL)
            self.verifyButton.config(state=tk.NORMAL)


    def signPdf(self):
        
        self.drive = self.findKeyFile()
        if not self.drive:
            messagebox.showerror("Error", "Pendrive not found")
            return None

        pin = self.getPin()
        if not pin:
            return
        
        privateKey = self.getPrivateKey(pin)
        if privateKey:
            with open(self.pdfPath, "rb") as file:
                pdfData = file.read()
            
            signature = privateKey.sign(
                pdfData,
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            with open(self.pdfPath + ".sig", "wb") as sigFile:
                sigFile.write(signature)

            messagebox.showinfo("Success", "PDF Signed Successfully!")
            self.statusLabel.config(text="Status: PDF Signed", fg="green")


    def getPin(self):
        pin = None
        while not pin:
            pin = tk.simpledialog.askinteger("PIN", "Enter your PIN:")
            if not pin:
                if not messagebox.askokcancel("PIN", "PIN cannot be empty. Do you want to try again?"):
                    return None
        return pin

    def getPrivateKey(self, pin):

        try:
            with open(f"{self.drive}/encryptedPrivateKey.key", "rb") as file:
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


    def findKeyFile(self):

        for part in psutil.disk_partitions():
            if "removable" in part.opts:
                drive = part.mountpoint
                for root, dirs, files in os.walk(drive):
                    if any(file.endswith(".key") for file in files):
                        self.statusPendrive.config(text=f"Pendrive status: Pendrive found", fg="green")
                        return drive
                    
        self.statusPendrive.config(text=f"Pendrive status: Pendrive not found", fg="red")
        return None

    def verifySignature(self):
        publicKey = self.getPublicKey()
        if not publicKey:
            return
        
        with open(self.pdfPath, "rb") as file:
            pdfData = file.read()

        try:
            with open(self.pdfPath + ".sig", "rb") as sigFile:
                signature = sigFile.read()
            
            publicKey.verify(
                signature,
                pdfData,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            messagebox.showinfo("Success", "Signature is valid!")
            self.statusLabel.config(text="Status: Signature Verified", fg="green")
        
        except Exception as e:
            messagebox.showerror("Error", "Signature is invalid!")
            self.statusLabel.config(text="Status: Signature Invalid", fg="red")
        
    
    def getPublicKey(self):

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
        

def main():
    app = tk.Tk()
    PAdESApp(app)
    app.mainloop()

if __name__ == "__main__":
    main()