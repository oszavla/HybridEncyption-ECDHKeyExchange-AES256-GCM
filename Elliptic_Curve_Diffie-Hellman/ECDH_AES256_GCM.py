from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii

# Encryption steps using the AES (Advanced Encryption Standard) algorithm in GCM (Galois/Counter Mode)
def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

# Decryption steps using the AES (Advanced Encryption Standard) algorithm in GCM (Galois/Counter Mode)

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

# takes an elliptic curve point as input and transforms it into a 256-bit key using the SHA-256 hashing algorithm.
def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()
    # point.x represents the x-coordinate of the elliptic curve point.
    # int.to_bytes(point.x, 32, 'big') converts this integer x-coordinate into a
    #   byte string. The 32 indicates that the byte string should be 32 bytes long
    #   (256 bits), and 'big' specifies big-endian byte order.
    # hashlib.sha256(...) initializes a SHA-256 hash object with the byte
    #   representation of the x-coordinate. SHA-256 is a cryptographic hash function
    #   that produces a 256-bit (32-byte) hash value.

# THE CORE PROCESS
# Elliptic curve used as long as the encryption/decryption process
curve = registry.get_curve('brainpoolP256r1')
print('Curve :', curve)
# brainpoolP256r1 => y^2 = x^3 +
#   56698187605326110043627228396178346077120614539475214109386828188763884139993x
#   +
#   17577232497321838841075697789794520262950426058923084567046852300633325438902
#   (mod
#   76884956397045344220809746629001649093037950200943055203735601445031516197751)
# THE CORE OF ELLIPTIC CURVE CRYPTOGRAPHY - ELLIPTIC CURVE DIFFIE HELLMAN KEY EXCHANGE
#   a   = Alice Privat Key = privKey,
#   a*G = Alice Public Key = pubKey,
#   b   = Bob Privat Key = ciphertextPrivKey,
#   b*G = Bob Public Key = ciphertextPubKey.
#   Secret Key ====> (a*G)*b = (b*G)*a
#   G is agreed points (Base Point) by Alice and Bob which have to exist over finite Galois field of elliptic Curve

# ----ENCRYPTION----
def encrypt_ECC(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    print('Bob privat key', ciphertextPrivKey)
    print('Bob public key', ciphertextPubKey)
    print('Base Point G', curve.g)
    return (ciphertext, nonce, authTag, ciphertextPubKey)

# ----DECRYPTION---
def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext

# Input plain test image (binary data)
input_binary_data_path = r"C:\Users\ASUS\CompPhyPy\Data_Komputasi\Cryptography_Final_Project\test_image_binary.txt"
with open(input_binary_data_path, 'r') as f:
    binary_str_data = f.read().replace('\n', '')
msg = binary_str_data.encode('utf-8')
# print("original msg:", msg)

# Generate random base point in Galois field elliptic curve brainpoolP256r1
privKey = secrets.randbelow(curve.field.n)  # Alice Privat Key == a
pubKey = privKey * curve.g                  # Alice Public Key == a*G
print('Maximum Prime Number',curve.field.n)
print('Alice privat key :', privKey)
print('Alice public key :', pubKey)

encryptedMsg = encrypt_ECC(msg, pubKey)
decryptedMsg = decrypt_ECC(encryptedMsg, privKey)

print('random AES initialization vector (nonce)', encryptedMsg[1])
print('Autentication Tag', encryptedMsg[2])

encrypted_binary_path = '/content/drive/MyDrive/OszavlaDrive/Dokumen/Akademik/Cryptography_Final_Project/encrypted_binary.txt'
decrypted_binary_path = '/content/drive/MyDrive/OszavlaDrive/Dokumen/Akademik/Cryptography_Final_Project/decrypted_binary.txt'

# encryptedMsg[0] contains the raw ciphertext bytes
encrypted_bytes = encryptedMsg[0]
# decryptedMsg contains the raw decrypted text bytes
decrypted_bytes = decryptedMsg

# Convert raw ciphertext bytes to a string of '0's and '1's
encrypted_binary_str = ''.join(f'{byte:08b}' for byte in encrypted_bytes)
with open(encrypted_binary_path, 'w') as f:
    f.write(encrypted_binary_str)

# Convert raw decrypted text bytes (which is the original binary string encoded) back to a string
decrypted_binary_str = decrypted_bytes.decode('utf-8')
with open(decrypted_binary_path, 'w') as f:
    f.write(decrypted_binary_str)

print(f"Ciphertext (binary string) for visual comparison saved to {encrypted_binary_path}")
print(f"Decrypted (binary string) for visual comparison saved to {decrypted_binary_path}")
