# USB Device Security Assessment Tool

A comprehensive Python tool for USB device security assessment and fuzzing. This tool enables blackbox analysis of USB devices through endpoint enumeration, descriptor analysis, brute-force scanning, Monte Carlo fuzzing, and command expansion.

## Features

- **Device Enumeration**: List all USB devices with detailed configuration information
- **Descriptor Analysis**: Enumerate USB descriptors with brute-force capability
- **Single Command Sending**: Send individual hex commands and view responses
- **Batch Command Sending**: Send multiple commands from a file
- **Brute-Force Scanning**: Exhaustively test all byte combinations up to specified length
- **Monte Carlo Fuzzing**: Random fuzzing with configurable payload lengths
- **Command Expansion**: Test variations of known successful commands
- **Comprehensive Logging**: Record all commands, responses, and traffic to multiple formats
- **Flexible Device Selection**: Select devices by index or VID/PID
- **Pattern Skipping**: Skip specific byte patterns during scanning

## Prerequisites

- Python 3.x
- `pyusb` library
- `libusb` backend

## Installation

1. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

2. Install libusb backend:
   - **macOS**: `brew install libusb`
   - **Linux**: `sudo apt-get install libusb-1.0-0-dev`
   - **Windows**: Install libusb-win32 driver

3. Run with appropriate permissions:
   ```bash
   # Linux/macOS
   sudo python explore_usb_device.py [options]
   ```

## Usage

### 1. Enumerate USB Devices

List all available USB devices with their configurations, interfaces, and endpoints:

```bash
python explore_usb_device.py --enumerate
```

**Output includes:**
- Vendor ID (VID) and Product ID (PID)
- Manufacturer and product strings
- All configurations and interfaces
- USB class information (HID, Mass Storage, Vendor Specific, etc.)
- All endpoints with direction, type, and attributes

### 2. Get USB Descriptors

Enumerate USB descriptors by trying different descriptor types and indexes:

```bash
# Basic descriptor enumeration (standard types only)
sudo python explore_usb_device.py --get-descriptors 1

# Specify maximum index to test (default: 255)
sudo python explore_usb_device.py --get-descriptors 1 50

# Brute-force all descriptor types (0x00-0xFF)
sudo python explore_usb_device.py --get-descriptors 1 --bruteforce-descriptors

# Use VID/PID instead of device index
sudo python explore_usb_device.py --get-descriptors 0 --vid 0x1234 --pid 0x5678

# Enable logging
sudo python explore_usb_device.py --get-descriptors 1 --log
sudo python explore_usb_device.py --get-descriptors 1 --bruteforce-descriptors --log descriptor_scan
```

**Descriptor types tested (standard mode):**
- DEVICE (0x01)
- CONFIGURATION (0x02)
- STRING (0x03) - automatically decoded to text
- INTERFACE (0x04)
- ENDPOINT (0x05)
- DEVICE_QUALIFIER (0x06)
- OTHER_SPEED_CONFIGURATION (0x07)
- HID (0x21)
- REPORT (0x22)
- PHYSICAL (0x23)

### 3. Send Single Command

Send a specific hex command to a USB device and view the response. This is useful for testing known commands or manually interacting with a device.

**Note**: Requires `sudo` on Linux/macOS for device access.

```bash
# Send a command with space-separated hex bytes
sudo python explore_usb_device.py --send-command 2 "AA BB CC DD"

# Send a command with continuous hex string
sudo python explore_usb_device.py --send-command 2 "AABBCCDD"

# Use VID/PID instead of device index
sudo python explore_usb_device.py --send-command 0 "01 02 03" --vid 0x1234 --pid 0x5678

# Enable logging to capture command and response
sudo python explore_usb_device.py --send-command 2 "AA BB CC" --log command_test
```

**Command format:**
- Hex bytes can be space-separated: `"AA BB CC DD"`
- Or continuous: `"AABBCCDD"`
- Case insensitive: `"aabbccdd"` or `"AABBCCDD"`
- Comments in files start with `#`

**Output includes:**
- Command bytes in hex format
- Command length
- USB interface and endpoint information
- Response data in both hex and ASCII formats
- Timeout notification if no response received

### 4. Send Commands from File

Send multiple hex commands from a file, with one command per line. Each command is sent sequentially with the response displayed.

```bash
# Basic usage
sudo python explore_usb_device.py --send-file 2 commands.txt

# With logging enabled
sudo python explore_usb_device.py --send-file 2 commands.txt --log batch_test

# Use VID/PID instead of device index
sudo python explore_usb_device.py --send-file 0 commands.txt --vid 0x1234 --pid 0x5678
```

**File format example (`commands.txt`):**
```text
# This is a comment - lines starting with # are ignored
AA BB CC DD
01 02 03 04 05
AABBCCDD
# Another comment
FF EE DD CC BB AA

# Blank lines are also ignored
40 50 60
```

**Features:**
- One command per line
- Lines starting with `#` are treated as comments and ignored
- Blank lines are skipped
- Mix space-separated and continuous hex formats
- Progress indicator shows which command is being sent
- Small delay between commands to avoid overwhelming the device

### 5. Scan Mode (Direct Fuzzing)

Perform direct fuzzing on a USB device using brute-force or Monte Carlo methods.

#### Brute-Force Scanning

Exhaustively test all byte combinations up to specified length:

```bash
# Scan all 1-byte commands (256 combinations)
sudo python explore_usb_device.py --scan 2 --bruteforce 1

# Scan up to 2-byte commands (65,536 combinations)
sudo python explore_usb_device.py --scan 2 --bruteforce 2

# With logging enabled
sudo python explore_usb_device.py --scan 2 --bruteforce 2 --log

# With prefix and postfix
sudo python explore_usb_device.py --scan 2 --bruteforce 2 --prefix "AA BB" --postfix "FF"

# Skip certain patterns
sudo python explore_usb_device.py --scan 2 --bruteforce 1 --skip "00" --skip "*FF"
```

#### Monte Carlo Scanning

Random fuzzing with configurable parameters:

```bash
# 10,000 iterations, payload length 1-4 bytes
sudo python explore_usb_device.py --scan 2 --monte-carlo 10000 1 4

# With prefix (prepend bytes to all commands)
sudo python explore_usb_device.py --scan 2 --monte-carlo 10000 1 4 --prefix "AA BB"

# With postfix (append bytes to all commands)
sudo python explore_usb_device.py --scan 2 --monte-carlo 5000 2 8 --postfix "CC DD"

# With both prefix and postfix
sudo python explore_usb_device.py --scan 2 --monte-carlo 10000 1 1 --prefix "ab334f6d"

# With logging and skip patterns
sudo python explore_usb_device.py --scan 2 --monte-carlo 10000 1 4 --log fuzzing_session --skip "*00*"
```

### 6. Expand Mode (Command Expansion)

Read known successful commands from a file and expand them with fuzzing to discover variations.

#### Input File Format

Create a text file with hex commands (one per line). They can be retrieved from previously generated logs:

```text
CMD: AA BB CC
CMD: 9f 7a d1 01 04
CMD: 40 50
```

#### Progressive Prefix Mode (Default)

Tests progressively longer prefixes from each command:

```bash
# Default: Monte Carlo with 1-4 byte suffix, 1000 iterations per prefix
sudo python explore_usb_device.py --expand-cmds 2 commands.txt 1000

# Custom Monte Carlo range
sudo python explore_usb_device.py --expand-cmds 2 commands.txt 1000 --monte-carlo-expand 1 8

# Brute-force suffix (exhaustive up to 2 bytes)
sudo python explore_usb_device.py --expand-cmds 2 commands.txt 1000 --bruteforce-expand 2

# With logging
sudo python explore_usb_device.py --expand-cmds 2 commands.txt 1000 --log expansion_session
```

**Example behavior (command: AA BB CC):**
1. Tests: `AA` + random bytes
2. Tests: `AA BB` + random bytes
3. Tests: `AA BB CC` + random bytes

#### Suffix Mode

Keeps the full command intact and only appends bytes:

```bash
# Suffix mode with Monte Carlo
sudo python explore_usb_device.py --expand-cmds 2 commands.txt 1000 --suffix-mode

# Suffix mode with custom range
sudo python explore_usb_device.py --expand-cmds 2 commands.txt 1000 --suffix-mode --monte-carlo-expand 1 8

# Suffix mode with brute-force
sudo python explore_usb_device.py --expand-cmds 2 commands.txt 1000 --suffix-mode --bruteforce-expand 2

# With postfix (appended after all random bytes)
sudo python explore_usb_device.py --expand-cmds 2 commands.txt 1000 --suffix-mode --postfix "FF FF"
```

**Example behavior (command: AA BB CC):**
- Tests: `AA BB CC` + random/exhaustive bytes

## Device Selection

### By Enumeration Index

```bash
# First, list devices
python explore_usb_device.py --enumerate

# Then use the device number
sudo python explore_usb_device.py --scan 2 --monte-carlo 1000 1 4
```

### By VID/PID

```bash
sudo python explore_usb_device.py --scan 0 --vid 0x1234 --pid 0x5678 --monte-carlo 1000 1 4
```

## Logging System

When `--log` is enabled, the tool creates a session folder with 10 files:

### Binary Files
- **commands-all.bin**: All commands sent (raw binary)
- **commands-acked.bin**: Commands that received responses (raw binary)
- **cmd-resp.bin**: Command-response pairs (raw binary)
- **responses.bin**: All responses received (raw binary)
- **traffic.bin**: Complete traffic log (raw binary)

### Text Files (Hex Format)
- **commands-all.txt**: All commands sent (hex)
- **commands-acked.txt**: Commands that received responses (hex)
- **cmd-resp.txt**: Command-response pairs with labels (hex)
- **responses.txt**: All responses received (hex)
- **traffic.txt**: Complete traffic log with CMD/RSP labels (hex)

### Usage

```bash
# Default folder name: session_YYYYMMDD_HHMMSS
sudo python explore_usb_device.py --scan 2 --monte-carlo 1000 1 4 --log

# Custom folder name
sudo python explore_usb_device.py --scan 2 --bruteforce 2 --log my_scan_session

# Logging with descriptor enumeration
sudo python explore_usb_device.py --get-descriptors 1 --bruteforce-descriptors --log descriptor_dump
```

**Note**: When running as root, the tool automatically changes ownership of log files to the script owner.

## Skip Patterns

Control which byte patterns to avoid during scanning:

```bash
# Skip exact single-byte command
--skip "40"           # Skips only the command [0x40]

# Skip commands starting with byte
--skip "40*"          # Skips [0x40], [0x40 0x??], [0x40 0x?? 0x??], etc.

# Skip commands ending with byte
--skip "*40"          # Skips [0x40], [0x?? 0x40], [0x?? 0x?? 0x40], etc.

# Skip commands containing byte
--skip "*40*"         # Skips any command with 0x40 anywhere

# Multiple skip patterns
--skip "00" --skip "*FF" --skip "40*"
```

### Example Usage

```bash
# Avoid null bytes and commands starting with 0xFF
sudo python explore_usb_device.py --scan 2 --bruteforce 2 --skip "*00*" --skip "FF*"

# Skip specific problematic commands
sudo python explore_usb_device.py --scan 2 --monte-carlo 10000 1 4 --skip "40" --skip "80"
```

## Prefix and Postfix

Add fixed bytes before and/or after all test payloads:

```bash
# Prepend header bytes
sudo python explore_usb_device.py --scan 2 --monte-carlo 1000 1 4 --prefix "AA BB"

# Append footer bytes
sudo python explore_usb_device.py --scan 2 --monte-carlo 1000 1 4 --postfix "CC DD"

# Both prefix and postfix
sudo python explore_usb_device.py --scan 2 --bruteforce 1 --prefix "9f24c60664" --postfix "FF"
```

**Result**: Tests commands like: `[prefix] [payload] [postfix]`

## Complete Examples

### Example 1: Initial Device Assessment

```bash
# 1. List all devices
python explore_usb_device.py --enumerate

# 2. Get descriptors for device #2
sudo python explore_usb_device.py --get-descriptors 2 --log initial_descriptors

# 3. Quick scan for 1-byte commands
sudo python explore_usb_device.py --scan 2 --bruteforce 1 --log scan_1byte
```

### Example 2: Targeted Fuzzing

```bash
# Known prefix from descriptor analysis
sudo python explore_usb_device.py --scan 2 --monte-carlo 10000 1 4 \
  --prefix "ab334f6d" --log targeted_fuzz

# Extract successful commands
grep "MATCH" session_*/cmd-resp.txt > successful_commands.txt

# Expand successful commands
sudo python explore_usb_device.py --expand-cmds 2 successful_commands.txt 1000 \
  --suffix-mode --monte-carlo-expand 1 8 --log expansion
```

### Example 3: Comprehensive Descriptor Analysis

```bash
# Brute-force all descriptor types with full index range
sudo python explore_usb_device.py --get-descriptors 1 255 \
  --bruteforce-descriptors --log full_descriptors

# Analyze the results
cat session_*/responses.txt | grep -v "^$" | wc -l  # Count found descriptors
```

### Example 4: Send Known Commands

```bash
# Send a single test command
sudo python explore_usb_device.py --send-command 2 "AA BB CC DD"

# Send multiple commands from a file
sudo python explore_usb_device.py --send-file 2 example_commands.txt --log command_testing

# Test commands with specific device
sudo python explore_usb_device.py --send-command 0 "01 02 03" --vid 0x1234 --pid 0x5678
```

### Example 5: Exploration

```bash
sudo python explore_usb_device.py --scan 2 --monte-carlo 5000 2 6 \
  --skip "*00*" --skip "FF*" --skip "*80" \
  --log safe_exploration
```

## Example Commands File

An `example_commands.txt` file is included to demonstrate the file format for batch command sending. The format supports:

- Space-separated hex bytes: `AA BB CC DD`
- Continuous hex strings: `AABBCCDD`
- Comments starting with `#`
- Blank lines (ignored)
- Case-insensitive hex values

## Troubleshooting

### Permission Denied

Run with sudo/administrator privileges:
```bash
sudo python explore_usb_device.py --enumerate
```

## Safety Considerations

**Warning**: This tool sends arbitrary data to USB devices and can:
- Cause unexpected device behavior
- Trigger firmware bugs
- Reset or damage devices
- Void warranties

## License

BSD 3-Clause License

Copyright (c) 2025, Gabriel Gonzalez Garcia - www.gabrielcybersecurity.com

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Disclaimer

This tool is provided for **educational and authorized security research purposes only**.

**Warning**: Unauthorized access to computer systems is illegal. Always ensure you have proper authorization before testing any device or system.

The authors assume no liability for misuse or damage caused by this tool. Users are responsible for compliance with all applicable laws and regulations.
