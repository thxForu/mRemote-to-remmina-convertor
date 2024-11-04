import os
import logging
import configparser
import xml.etree.ElementTree as ET
from src.config import decrypt_mremote_password, encrypt_remmina_password

logger = logging.getLogger(__name__)


def process_connections(args):
    """Process all connections from XML file"""
    duplicates = set()

    try:
        tree = ET.parse(args["input_file"])
        root = tree.getroot()

        for item in root:
            if item.attrib.get("Type") == "Connection":
                name = item.attrib.get("Name", "")
                create_connection(item, name, args, duplicates)

    except ET.ParseError as e:
        logger.error(f"Error parsing XML file: {e}")
        raise


def create_connection(item, parents, args, duplicates):
    """Create connection configuration"""
    if item.attrib["Name"] in duplicates:
        logger.warning(f"Duplicate connection found: {item.attrib['Name']}")
        return

    duplicates.add(item.attrib["Name"])

    config = configparser.ConfigParser()
    config["remmina"] = {}
    conf = config["remmina"]

    # Basic configuration
    protocol = item.attrib["Protocol"]
    if protocol in ("SSH", "SSH1", "SSH2"):
        conf["protocol"] = "SSH"
        conf["ssh_color_scheme"] = "3"
    elif protocol == "RDP":
        conf["protocol"] = "RDP"
    elif protocol == "HTTP":
        conf["protocol"] = "HTTP"
    else:
        logger.warning(f"Unsupported protocol: {protocol}")
        return

    # General settings
    conf["name"] = item.attrib["Name"]
    conf["server"] = f"{item.attrib['Hostname']}:{item.attrib['Port']}"
    conf["group"] = "Converted"

    # Handle passwords if needed
    if args["password"]:
        handle_password(item, conf, args["password_value"])

    # Save configuration file
    parents = parents.replace("/", "").replace("\\", "").replace("\t", "")
    file_path = os.path.join(args["output_file"], f"{parents}.remmina")

    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w") as configfile:
            config.write(configfile)
        logger.info(f"Successfully saved: {file_path}")
    except Exception as e:
        logger.error(f"Error saving config file: {e}")


def handle_password(item, conf, password_value):
    """Handle passwords for connection"""
    try:
        if item.attrib["Password"]:
            decrypted = decrypt_mremote_password(item.attrib["Password"])
            if decrypted:
                encrypted = encrypt_remmina_password(password_value, decrypted)
            else:
                encrypted = ""
        else:
            encrypted = ""

        if conf["protocol"] == "SSH":
            conf["ssh_username"] = item.attrib["Username"]
            conf["ssh_password"] = encrypted
        elif conf["protocol"] == "RDP":
            conf["username"] = "" if item.attrib["Username"] == "ldapname if you want" else item.attrib["Username"]
            conf["password"] = encrypted
    except Exception as e:
        logger.error(f"Error handling password for {item.attrib['Name']}: {e}")