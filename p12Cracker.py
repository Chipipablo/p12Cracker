#!/usr/bin/env python3
"""
Brute-force a PKCS#12 (.p12/.pfx) file using a wordlist.
Uses the 'cryptography' library to load PKCS#12 data (recommended over older pyOpenSSL APIs).

Changes:
- At the end prints the total number of keys tried.
- Every 1000 attempts prints a progress line indicating the number of attempts.
"""

import argparse
import sys
import itertools
from colorama import init as colorama_init, Fore, Style
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization

colorama_init(autoreset=True)


def spinner_generator():
    """
    Simple infinite spinner generator that yields characters to show progress.
    """
    for ch in itertools.cycle("|/-\\"):
        yield ch


def print_error_and_exit(message: str, code: int = 1):
    """
    Print a red error message and exit with the provided code.
    """
    print(Fore.RED + Style.BRIGHT + "Error:" + Style.RESET_ALL + " " + Fore.RED + message)
    sys.exit(code)


def try_load_p12(p12_bytes: bytes, password: bytes):
    """
    Try to load the PKCS#12 bytes using the given password (bytes or None).
    Returns (True, (private_key, cert, additional_certs)) on success, (False, None) on failure.
    """
    try:
        pwd = password if password else None
        private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(p12_bytes, pwd)
        # Consider success if either private key or certificate is present
        if private_key is not None or certificate is not None:
            return True, (private_key, certificate, additional_certs)
        return False, None
    except Exception:
        # Most incorrect passwords raise an exception (ValueError or similar)
        return False, None


def save_key_and_cert(private_key, certificate, key_path="key.pem", cert_path="cert.pem", key_password: bytes = None):
    """
    Save private key and certificate to PEM files.
    If key_password is provided (bytes), the private key will be encrypted with it.
    """
    # Serialize and save private key
    if private_key is not None:
        if key_password:
            encryption = serialization.BestAvailableEncryption(key_password)
        else:
            encryption = serialization.NoEncryption()
        pem_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption,
        )
        with open(key_path, "wb") as kf:
            kf.write(pem_key)

    # Serialize and save certificate
    if certificate is not None:
        pem_cert = certificate.public_bytes(encoding=serialization.Encoding.PEM)
        with open(cert_path, "wb") as cf:
            cf.write(pem_cert)


def main():
    parser = argparse.ArgumentParser(description="Brute-force password for a .p12/.pfx (PKCS#12) file using a wordlist.")
    parser.add_argument("--p12-path", required=True, help="Path to the .p12/.pfx file")
    parser.add_argument("--wordlist", required=True, help="Path to the wordlist file (one password per line)")
    parser.add_argument("--save", action="store_true", help="If set, save decrypted private key and certificate to key.pem and cert.pem when password is found")
    parser.add_argument("--key-password", help="Optional password to encrypt saved private key (only meaningful with --save). If provided, the key will be encrypted with this password.", default=None)
    args = parser.parse_args()

    # Read PKCS#12 file into memory once (faster than reopening for every guess)
    try:
        with open(args.p12_path, "rb") as pf:
            p12_bytes = pf.read()
    except FileNotFoundError:
        print_error_and_exit(f".p12 file not found: {args.p12_path}")
    except Exception as exc:
        print_error_and_exit(f"Error opening .p12 file: {exc}")

    # Open the wordlist for streaming
    try:
        wordfile = open(args.wordlist, "r", encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        print_error_and_exit(f"Wordlist not found: {args.wordlist}")
    except Exception as exc:
        print_error_and_exit(f"Error opening wordlist: {exc}")

    spin = spinner_generator()
    attempts = 0
    progress_interval = 1000  # every N attempts print a progress message

    print("\n")
    print(Fore.CYAN + " Brute forcing...")
    print("\n")

    with wordfile:
        for raw_line in wordfile:
            guess = raw_line.rstrip("\n\r")
            # Show spinner character (do not reveal full password on screen)
            sys.stdout.write(next(spin))
            sys.stdout.flush()
            sys.stdout.write("\b")

            attempts += 1

            # Every 'progress_interval' attempts, print a progress line with the number of attempts
            if attempts % progress_interval == 0:
                # Move to new line to avoid overwriting spinner; then reprint a spinner placeholder afterwards
                sys.stdout.write("\n")
                print(Fore.YELLOW + f"[Progress] Attempts: {attempts}")
                # reprint spinner (next cycle) so progress continues inline
                sys.stdout.write(next(spin))
                sys.stdout.flush()
                sys.stdout.write("\b")

            password_bytes = guess.encode("utf-8") if guess != "" else b""

            success, details = try_load_p12(p12_bytes, password_bytes)
            if success:
                private_key, certificate, additional_certs = details
                print("\n")
                print(Fore.BLUE + "****************************************************************")
                print(f" {Fore.GREEN}Success!{Fore.RESET} Password cracked after {Fore.YELLOW}{attempts}{Fore.RESET} attempts.")
                print("\n")
                print(f" Password is: {Style.BRIGHT + Fore.RED}{guess}\n")
                print(Fore.BLUE + "****************************************************************")
                print("\n")

                if args.save:
                    # If user asked to save, optionally encrypt the saved private key with the provided password
                    key_pwd_bytes = args.key_password.encode("utf-8") if args.key_password else None
                    try:
                        save_key_and_cert(private_key, certificate, key_path="key.pem", cert_path="cert.pem", key_password=key_pwd_bytes)
                        print(Fore.GREEN + f"Saved private key to key.pem and certificate to cert.pem.")
                        if key_pwd_bytes:
                            print(Fore.GREEN + "Private key encrypted with the provided key password.")
                    except Exception as exc:
                        print(Fore.RED + f"Failed to save key/certificate: {exc}")

                # Final summary: total keys tried
                print(Fore.CYAN + f"Total keys tried: {attempts}")
                # Exit successfully
                sys.exit(0)

    # If reached here, no password matched
    print("\n" + Fore.RED + "Failed to crack the password - try again with a different wordlist\n")
    print(Fore.CYAN + f"Total keys tried: {attempts}")
    sys.exit(1)


if __name__ == "__main__":
    main()
