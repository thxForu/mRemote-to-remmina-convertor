import logging
import sys
import getopt
import configparser
from os.path import expanduser
import platform
import base64
import hashlib
from Crypto.Cipher import DES3, AES

# Constants
HOME = expanduser("~")
DEFAULT_OUTPUT = "Remmina" if platform.system() == "Windows" else f"{HOME}/.local/share/remmina/"
MREMOTE_DEFAULT_PASSWORD = "mR3m"

HELP_TEXT = """
MremoteNG to Remmina Config Converter.

Usage:
mremote_to_remmina.py -i mremote.xml
mremote_to_remmina.py -i mremote.xml -o "~/Desktop"
mremote_to_remmina.py -i mremote.xml -o "~/Desktop" -p
mremote_to_remmina.py -i mremote.xml -p

Options:
-h --help         Show this screen.
-i --inputFile    Location of XML File
-o --outputFolder Folder to Save .Remmina Files (DEFAULT is ~/.local/share/remmina)
-p --password     If You Want To Include Password *Must Be On Target Machine*
"""

logger = logging.getLogger(__name__)


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )


def parse_arguments():
    """Parse command line arguments"""
    try:
        opts, _ = getopt.getopt(
            sys.argv[1:], "hi:o:p", ["help", "ifile=", "ofolder=", "password"]
        )
    except getopt.GetoptError as err:
        logger.error(f"Error parsing arguments: {err}")
        print(
            f"*******************************************\n{err}\n*******************************************{HELP_TEXT}")
        sys.exit(2)

    if not opts:
        print(HELP_TEXT)
        sys.exit(2)

    args = {
        "input_file": None,
        "output_file": DEFAULT_OUTPUT,
        "password": False,
        "password_value": None
    }

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(HELP_TEXT)
            sys.exit()
        elif opt in ("-i", "--inputFile"):
            args["input_file"] = arg
        elif opt in ("-o", "--outputFolder"):
            args["output_file"] = arg
        elif opt in ("-p", "--password"):
            args["password"] = True
            try:
                config = configparser.ConfigParser()
                config.read(f"{HOME}/.config/remmina/remmina.pref")
                args["password_value"] = config["remmina_pref"]["secret"]
            except Exception as e:
                logger.error("Error reading Remmina config: %s", e)
                print("Error: Remmina isn't installed or configured properly")
                sys.exit(2)

    if not args["input_file"]:
        logger.error("Input file not specified")
        print("Error: you must enter -i <inputFile>")
        sys.exit(2)

    return args


def decrypt_mremote_password(encrypted_data: str) -> str:
    """Decrypt mRemoteNG password"""
    try:
        encrypted_data = base64.b64decode(encrypted_data)
        salt = encrypted_data[:16]
        associated_data = encrypted_data[:16]
        nonce = encrypted_data[16:32]
        ciphertext = encrypted_data[32:-16]
        tag = encrypted_data[-16:]

        key = hashlib.pbkdf2_hmac(
            "sha1",
            MREMOTE_DEFAULT_PASSWORD.encode(),
            salt,
            1000,
            dklen=32
        )

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(associated_data)

        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode("utf-8")
        except Exception as e:
            logger.error(f"Failed to decrypt password: {e}")
            return ""

    except Exception as e:
        logger.error(f"Error in password decryption: {e}")
        return ""


def encrypt_remmina_password(secret_password: str, plain: str) -> str:
    """Encrypt password for Remmina"""
    try:
        plain = plain.encode("utf-8")
        secret = base64.b64decode(secret_password)
        key = secret[:24]
        iv = secret[24:]
        plain = plain + b"\0" * (8 - len(plain) % 8)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        result = cipher.encrypt(plain)
        return base64.b64encode(result).decode("utf-8")
    except Exception as e:
        logger.error("Error encrypting password: %s", e)
        return ""
