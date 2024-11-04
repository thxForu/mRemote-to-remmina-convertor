# Convert mRemoteNG xml to Remmina files

This project was created to address stability issues with the deprecated mRemoteNG to Remmina converter project. It provides a reliable way to convert mRemoteNG XML configuration files to Remmina format.

## Features

- Converts mRemoteNG XML configurations to Remmina format
- Supports SSH, RDP, and HTTP protocols
- Handles password encryption/decryption
- Maintains connection groups and settings

## Requirements

```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python mremote_to_remmina.py -i mremote.xml
```

All available commands:
```bash
python mremote_to_remmina.py -i mremote.xml                    # Basic conversion
python mremote_to_remmina.py -i mremote.xml -o "~/Desktop"     # Custom output folder
python mremote_to_remmina.py -i mremote.xml -o "~/Desktop" -p  # With passwords
python mremote_to_remmina.py -i mremote.xml -p                 # With passwords
```

### Options

- `-h, --help` : Show usage information
- `-i, --inputFile` : Location of XML File
- `-o, --outputFolder` : Folder to save Remmina files (Default: ~/.local/share/remmina)
- `-p, --password` : Include passwords (requires Remmina to be installed)

## Important Notes

- When using the password option (-p), Remmina must be installed on the target machine
- The script preserves connection groups and basic settings
- Duplicate connection names are handled automatically

## Contributing

Contributions are welcome! Feel free to submit issues and pull requests.
