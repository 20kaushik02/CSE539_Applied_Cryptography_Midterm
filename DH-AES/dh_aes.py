import os
import argparse

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def prettyBytes(bytestr: bytes) -> str:
    """Prints byte strings like `\\x3d\\xe9\\xb7` as `3D E9 B7`"""
    return " ".join([bytestr[i : i + 1].hex().upper() for i in range(0, len(bytestr))])


def buildExpNum(exponent: int, constant: int, base: int = 2) -> int:
    return pow(base, exponent) - constant


def calculateSharedKey(
    g_e: int, g_c: int, N_e: int, N_c: int, x: int, gy_modN: int
) -> int:
    """Diffie-Hellman shared key computation (single-party)"""
    # g = build_exp_num(g_e, g_c) # not needed since gy_modN is given
    N = buildExpNum(N_e, N_c)
    return pow(gy_modN, x, N)


def encrypt(plaintext: bytes, key: int, iv: bytearray) -> bytes:
    """Encryption using AES-256 in CBC mode"""
    key_byte_length = 32
    cipher = Cipher(
        algorithms.AES(key.to_bytes(key_byte_length, byteorder="little")), modes.CBC(iv)
    )

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    encryptor = cipher.encryptor()
    return encryptor.update(padded_plaintext) + encryptor.finalize()


def decrypt(ciphertext: bytes, key: int, iv: bytearray) -> bytes:
    """Decryption using AES-256 in CBC mode"""
    key_byte_length = 32
    cipher = Cipher(
        algorithms.AES(key.to_bytes(key_byte_length, byteorder="little")), modes.CBC(iv)
    )

    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def main(args: argparse.Namespace) -> None:
    # pre-processing inputs
    iv = bytearray.fromhex(args.initialization_vector)
    g_e = int(args.g_e)
    g_c = int(args.g_c)
    N_e = int(args.N_e)
    N_c = int(args.N_c)
    x = int(args.x)
    gy_modN = int(args.gy_modN)
    ciphertext = bytearray.fromhex(args.ciphertext)
    plaintext = str.encode(args.plaintext, "utf-8")
    verbose = args.verbose

    shared_key = calculateSharedKey(g_e, g_c, N_e, N_c, x, gy_modN)
    if verbose:
        print(("-" * os.get_terminal_size().columns) + "\n")
        print("Shared key\t\t", shared_key)
        print(("-" * os.get_terminal_size().columns) + "\n")

    new_pt = decrypt(ciphertext, shared_key, iv)
    if verbose:
        print("Given ciphertext\t", prettyBytes(ciphertext))
        print("Calculated plaintext\t", new_pt.decode("utf-8"))
        print(("-" * os.get_terminal_size().columns) + "\n")

    new_ct = encrypt(plaintext, shared_key, iv)
    if verbose:
        print("Given plaintext\t\t", args.plaintext)
        print("Calculated ciphertext\t", prettyBytes(new_ct))
        print(("-" * os.get_terminal_size().columns) + "\n")

    if not verbose:
        print(f"{new_pt.decode('utf-8')}, {prettyBytes(new_ct)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DHKE keygen and AES encryption/decryption"
    )
    parser.add_argument("initialization_vector", help="")
    parser.add_argument("g_e", help="Exponent (base 2), for g")
    parser.add_argument("g_c", help="Constant to be subtracted, for g")
    parser.add_argument("N_e", help="Exponent (base 2), for N")
    parser.add_argument("N_c", help="Constant to be subtracted, for N")
    parser.add_argument("x", help="Alice's private key value")
    parser.add_argument("gy_modN", help="g^y modulo N, computed by Bob")
    parser.add_argument("ciphertext", help="Ciphertext to be decrypted")
    parser.add_argument("plaintext", help="Plaintext to be encrypted")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    main(args)
