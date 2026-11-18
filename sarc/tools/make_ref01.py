"""Builds ref_01_single_file.arc strictly from FORMAT_SPEC_P2 section 8."""
import hashlib, hmac, struct, sys, zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

out = sys.argv[1]

password = b"algo2026"
salt = bytes(range(16))
nonce = bytes([1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0])

data = b"hello world " * 40
assert len(data) == 480
crc = zlib.crc32(data)
print("crc32 =", format(crc, "08x"), "(spec: 70208846)")


def table(entries):
    b = struct.pack(">H", len(entries))
    for s, l in entries:
        b += struct.pack(">HB", s, l)
    return b


lit = table([(32, 3), (100, 4), (101, 4), (104, 4), (108, 2), (111, 3), (114, 4), (119, 3), (256, 3)])
ln = table([(207, 1), (255, 1)])
dist = table([(4, 1)])
stream = bytes.fromhex("ED06A3F315 9D18".replace(" ", ""))
block = lit + ln + dist + struct.pack(">II", 14, len(stream)) + stream
assert len(block) == 57, len(block)

payload = struct.pack(">HBB", 1, 0, 0)
payload += struct.pack(">H", 9) + b"hello.txt" + struct.pack(">II", 480, crc) + bytes([0, 1])
payload += struct.pack(">H", 1)
payload += struct.pack(">HIIIB", 0, 0, 480, 57, 0)
payload += block
assert len(payload) == 99, len(payload)

master = hashlib.pbkdf2_hmac("sha256", password, salt, 100000, 64)
k_enc, k_mac = master[:32], master[32:]

header = b"SARC" + bytes([1]) + struct.pack(">HH", 0, 1) + salt + nonce + struct.pack(">I", len(payload))
assert len(header) == 41

enc = Cipher(algorithms.AES(k_enc), modes.CTR(nonce + struct.pack(">I", 1))).encryptor()
cipher = enc.update(payload) + enc.finalize()
tag = hmac.new(k_mac, header + cipher, hashlib.sha256).digest()

arc = header + cipher + tag
print("archive length =", len(arc), "(spec: 172)")
open(out, "wb").write(arc)
