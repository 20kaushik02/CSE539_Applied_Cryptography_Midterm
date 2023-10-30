import os
import argparse


def buildExpNum(exponent: int, constant: int, base: int = 2) -> int:
    return pow(base, exponent) - constant


def gcdExtendedEuclidean(a: int, b: int) -> (int, int, int):
    if a == 0:
        return (b, 0, 1)
    gcd, x, y = gcdExtendedEuclidean(b % a, a)
    return (gcd, y - (b // a) * x, x)


def modularInverse(a: int, b: int) -> int:
    """Find modular inverse of `a` under modulo `b`"""
    g, x, y = gcdExtendedEuclidean(a, b)
    if g != 1:
        raise ValueError("non-coprime arguments provided")
    return x % b


def generatePrivateKey(e: int, p: int, q: int) -> (int, int):
    n = p * q
    lambda_n = (p - 1) * (q - 1) # Euler totient function
    d = modularInverse(e, lambda_n)

    # verify
    if (e * d) % lambda_n != 1:
        raise Exception("error computing d")
    return n, d


def decrypt(ciphertext: str, key: int, N: int) -> str:
    """RSA decryption with private key"""
    return str(pow(int(ciphertext), key, N))


def encrypt(plaintext: str, key: int, N: int) -> str:
    """RSA encryption with public key"""
    return str(pow(int(plaintext), key, N))


def main(args: argparse.Namespace) -> None:
    # pre-processing inputs
    p_e = int(args.p_e)
    p_c = int(args.p_c)
    q_e = int(args.q_e)
    q_c = int(args.q_c)
    e_e = int(args.e_e)
    e_c = int(args.e_c)
    ciphertext = str(args.ciphertext)
    plaintext = int(args.plaintext)
    verbose = args.verbose

    p = buildExpNum(p_e, p_c)
    q = buildExpNum(q_e, q_c)
    pub_key = e = buildExpNum(e_e, e_c)
    if verbose:
        print(("-" * os.get_terminal_size().columns) + "\n")
        print("Given public key (e)\t\t", pub_key)
        print(("-" * os.get_terminal_size().columns) + "\n")

    N, priv_key = generatePrivateKey(e, p, q)
    if verbose:
        print("Calculated private key (d)\t", priv_key)
        print(("-" * os.get_terminal_size().columns) + "\n")

    new_pt = decrypt(ciphertext, priv_key, N)
    if verbose:
        print("Given ciphertext\t\t", ciphertext)
        print("Decrypted plaintext\t\t", new_pt)
        print(("-" * os.get_terminal_size().columns) + "\n")

    new_ct = encrypt(plaintext, pub_key, N)
    if verbose:
        print("Given plaintext\t\t\t", plaintext)
        print("Encrypted ciphertext\t\t", new_ct)
        print(("-" * os.get_terminal_size().columns) + "\n")

    if not verbose:
        print(new_pt, new_ct)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extended Euclidean algorithm and RSA encryption/decryption"
    )
    parser.add_argument("p_e", help="Exponent (base 2), for p")
    parser.add_argument("p_c", help="Constant to be subtracted, for p")
    parser.add_argument("q_e", help="Exponent (base 2), for q")
    parser.add_argument("q_c", help="Constant to be subtracted, for q")
    parser.add_argument("e_e", help="Exponent (base 2), for e")
    parser.add_argument("e_c", help="Constant to be subtracted, for e")
    parser.add_argument("ciphertext", help="Ciphertext to be decrypted")
    parser.add_argument("plaintext", help="Plaintext to be encrypted")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    main(args)
