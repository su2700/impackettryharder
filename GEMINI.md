# Project: Impacket Command Template Generator

## Project Overview
This project provides a Python-based utility, `impackettryharder.py`, designed to generate command templates for various [Impacket](https://github.com/fortra/impacket) tools. It simplifies the process of constructing complex command-line strings for network security auditing and penetration testing.

### Main Technologies
- **Python 3**: The core language used for the script.
- **Argparse**: For handling command-line arguments.
- **Getpass**: For secure interactive password input.

### Architecture
The project is a single-file Python script (`impackettryharder.py`) organized into several logical sections:
- **Categories**: Defines groups of Impacket tools (e.g., `windows_rce`, `smb_tools`, `ad_kerberos`).
- **Generators**: Individual functions for each tool that construct the specific command string based on provided parameters (IP, user, domain, password/hash).
- **Builder**: Orchestrates the expansion of categories and calls the appropriate generators.
- **CLI/Interactive Interface**: Handles user input via command-line arguments or an interactive prompt, now featuring a **colorful ANSI-powered UI** for better readability.


## Building and Running

### Prerequisites
- Python 3.x
- (Optional but recommended) [Impacket](https://github.com/fortra/impacket) installed on the system where the generated commands will be executed.

### Running the Script
You can run the script in two modes:

#### 1. Interactive Mode
Simply execute the script without arguments to start an interactive prompt:
```bash
python3 impackettryharder.py
```
The script will guide you through entering the target details and selecting tool categories.

#### 2. CLI Mode
Provide arguments directly to generate templates without interactive prompts:
```bash
python3 impackettryharder.py --ip <TARGET_IP> --user <USERNAME> --domain <DOMAIN> --categories <CATEGORIES>
```
Example:
```bash
python3 impackettryharder.py --ip 192.168.1.10 --user Administrator --categories 1,3
```

### Help
To see all available command-line options:
```bash
python3 impackettryharder.py --help
```

## Development Conventions

- **Type Hinting**: The script uses Python type hints (`typing` module) for improved readability and static analysis.
- **Surgical Tool Generators**: Each Impacket tool has its own generator function (e.g., `gen_wmiexec`, `gen_secretsdump`) to handle its specific syntax and quirks.
- **Zsh Compatibility**: Generated command strings include logic for shell quoting (e.g., `quote_zsh`) to ensure they work correctly in Zsh environments.
- **Target OS Filtering**: The script includes a `SCRIPT_TARGET` mapping to filter commands based on whether they are intended for Windows or other operating systems.
