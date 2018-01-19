import sys
import hashlib

def read_blocks(filepath, size):
    with open(filepath, "rb") as file:
        while True:
            block = file.read(size)
            if not block:
                break
            yield bytearray(block)

def cbc(mode, password, iv, input, output):
    with open(output, "wb") as file:
        for block in read_blocks(input, len(password)):
            result = bytearray([block[i] ^ iv[i] ^ password[i] for i in range(0, len(block))])
            iv = result if mode == "encrypt" else block
            file.write(result)
