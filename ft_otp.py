#!/usr/bin/env python3
import argparse
from pathlib import Path
import hmac, hashlib, time, struct, qrcode, base64

def generate_qrcode(key: bytes, label: str = "ft_otp:user@example.com", issuer: str="ft_otp"):
    secret_b32 = base64.b32encode(key).decode("utf-8").replace("=","")
    uri = f"otpauth://totp/{label}?secret={secret_b32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"

    img = qrcode.make(uri)
    img.save("ft_otp.png")
    print("QR code enregistre dans ft_otp.png")
    print("URI :", uri)

def xor_data(data: bytes, password: str) -> bytes:
    pwd_bytes = password.encode()
    pwd_len = len(pwd_bytes)
    return bytes([b ^ pwd_bytes[i % pwd_len] for i , b in enumerate(data)])

def generate_totp(key: bytes, digits: int = 6, period: int = 30, now: float | None = None) -> str:
    if now is None:
        now = time.time()
    counter = int(now // period)
    counter_bytes = struct.pack(">Q", counter)

    hmac_digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = hmac_digest[-1] & 0x0f
    part = hmac_digest[offset:offset + 4]

    code = ((part[0] & 0x7F) << 24) | ((part[1] & 0xFF) << 16) | ((part[2] & 0xFF) << 8) | ((part[3] & 0xFF))
    otp = code % (10 ** digits)
    return str(otp).zfill(digits)

def main():
    parser = argparse.ArgumentParser(description="Ft_otp - Generateur TOTP (RFC 6238)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-g", dest="hexfile", metavar="HEXFILE", help="Cle hexadecimal pour generer le fichier ft_otp.key")
    group.add_argument("-k", dest="keyfile", metavar="KEYFILE", help="Chemin vers le fichier chiffre" )
    parser.add_argument("-p", dest="password",metavar="PASSWORD", help="Mots de passe pour chiffrer/dechiffrer la cle" )
    parser.add_argument("--qrcode",action="store_true", help="creation d un qrcode pour google authenticator" )
    args = parser.parse_args()

    if args.hexfile:
        print(f"[MODE -g] Fichier cle hex : {args.hexfile}")
    elif args.keyfile:
        print(f"[MODE -k] Fichier cle chiffree : {args.keyfile}")

    if args.hexfile:
        if not args.password:
            print("Erreur : -p Password est requis pour chiffree ft_otp.key")
            return 1
        try:
            cle = bytes.fromhex(args.hexfile)
        except ValueError:
            print("Erreur : Cle hex invalide")
            return 1
        if len(cle) < 32:
            print("Erreur : la cle doit faire au moins 64 caracteres hex (32 octet)")
            return 1
        encrypted = xor_data(cle, args.password)
        Path("ft_otp.key").write_bytes(encrypted)
        print("Cle enregistrer dans ft_otp.key")

    if args.keyfile:
        try:
            key_path = Path(args.keyfile)

            if not key_path.is_file():
                print(f"Erreur: fichier introuvable : {key_path}")
                return 1
            cle = key_path.read_bytes()
            if args.password:
                cle = xor_data(cle, args.password)
        except PermissionError:
            print(f"Erreur : permission refusee pour lire {args.keyfile}")
            return 1
        except OSError as e:
            print(f"Erreur d entree/sortie sur {args.keyfile}: {e}")
            return 1
        
        if not cle:
            print("Erreur : fichier cle vide")
            return 1
        
        if len(cle) < 32:
            print(f"Erreur : clé déchiffrée trop courte ({len(cle)} octets). Attendu >= 32 octets.")
            return 1

        print("[MODE -k] Cle chargee :")
        print(f"    - chemin : {key_path.resolve()}")
        print(f"    - taille : {len(cle)} octet")
        preview = cle.hex()
        if len(preview) > 32:
            preview = preview[:32] + "..."
        print(f"    - apercu : {preview}")
        otp = generate_totp(cle, digits=6, period=30)
        if args.qrcode:
            generate_qrcode(cle, label=args.qrcode, issuer="ft_otp")
        print(f"\nOTP : {otp}")

if __name__ == "__main__":
    exit(main())