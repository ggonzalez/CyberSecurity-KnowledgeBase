# GaBL-E: BLE Fuzzer

A Bluetooth Low Energy (BLE) fuzzer designed for macOS security testing.

## Features

- **Device Scanning**: Discover BLE devices in range with two display modes
  - Short mode: Shows device number, name, UUID, and RSSI for quick identification
  - Verbose mode: Shows comprehensive information including:
    - Device name and UUID
    - RSSI (signal strength)
    - Service UUIDs
    - Manufacturer data
    - Service data
    - TX Power Level
    - Local name
    - Connectable status
    - All available metadata and advertisement data
  
- **Device Connection**: Connect to specific BLE devices by UUID

- **Characteristic Enumeration**: Retrieve and display all services, characteristics, and descriptors
  - Identifies service types (Generic Access, Device Information, Battery, Custom, etc.)
  - Groups characteristics by service type for easy navigation
  - Clear display of READ/WRITE capabilities
  - Shows all properties (read, write, notify, indicate, etc.)
  - Summary section with quick reference organized by capability:
    - Read/Write (both capabilities)
    - Read-Only
    - Write-Only

- **READ/WRITE Operations**: Perform individual read and write operations on specific characteristics
  - Read single characteristic by UUID
  - Read all readable characteristics at once using `*` wildcard
  - Write to characteristics with hex data input
  - Displays data in hexdump format with ASCII representation
  - Automatic UTF-8 decoding when applicable

- **Fuzzing Capabilities**: Comprehensive fuzzing modes for security testing
  - **Single Characteristic Fuzzing**: Target a specific writable characteristic
    - Configurable iteration count (default: 10,000)
    - Optional read-after-write for read/write characteristics
    - Generates various data patterns (random, zeros, ones, patterns, boundaries)
    - Real-time progress tracking with success/failure stats
    - Keyboard interrupt support (Ctrl+C)
  
  - **All Characteristics Fuzzing**: Fuzz all writable characteristics sequentially
    - Automatically discovers all writable characteristics
    - Applies fuzzing to each characteristic
    - Progress tracking per characteristic
    - Comprehensive summary statistics
  
  - **Write-All/Read-All Fuzzing**: Comprehensive state dump mode
    - Writes fuzz data to all writable characteristics
    - Reads all readable characteristics after each write cycle
    - Useful for discovering state-dependent behaviors
    - High-speed iteration for maximum coverage

## Requirements

- macOS (tested on macOS 11+)
- Python 3.7 or higher
- Bleak library

## Installation

1. Clone the repository:
```bash
git clone <repo-url>
cd GaBL-E
```

2. Create and activate a virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Interactive Mode

Use the `--interactive` flag to enter interactive mode:
```bash
python3 gable.py --interactive
```

In interactive mode, you can:
1. Scan for devices (short or verbose)
2. Connect to a device by UUID
3. When connected, additional options appear:
   - Enumerate all characteristics (grouped by service type)
   - Read specific characteristics
   - Write to specific characteristics
   - Fuzz single characteristic
   - Fuzz all writable characteristics
   - Fuzz with write-all/read-all mode
   - Disconnect from device

The prompt changes to `connected>` when you're connected to a device, and menu options adapt based on connection status.

### Command Line Mode

**Scan for devices (short format):**
```bash
python3 gable.py --scan
```

**Scan for devices (verbose format):**
```bash
python3 gable.py --scan --verbose
```

**Scan with custom duration:**
```bash
python3 gable.py --scan --duration 10
```

**Connect to a device and enumerate characteristics:**
```bash
python3 gable.py --mac 12345678-ABCD-1234-ABCD-123456789ABC --enumerate
```

**Note**: The `--mac` parameter accepts the device UUID (not a traditional MAC address).

## Examples

### Example 1: Quick Scan
```bash
python3 gable.py -s
```

### Example 2: Detailed Scan
```bash
python3 gable.py -s -v -d 10
```

### Example 3: Connect and Enumerate
```bash
# Use the UUID from your scan results
python3 gable.py -m 12345678-ABCD-1234-ABCD-123456789ABC -e
```

### Example 4: Fuzz a Specific Characteristic
```bash
# Fuzz with 5000 iterations
python3 gable.py --mac 12345678-ABCD-1234-ABCD-123456789ABC \
  --fuzz-char 0000fff1-0000-1000-8000-00805f9b34fb \
  --iterations 5000
```

### Example 5: Fuzz All Writable Characteristics
```bash
# Comprehensive fuzzing of all writable characteristics
python3 gable.py --mac 12345678-ABCD-1234-ABCD-123456789ABC \
  --fuzz-all --iterations 10000 --read-after-write
```

This will display all services and characteristics with clear capability indicators:
```
[Service] 00001800-0000-1000-8000-00805f9b34fb
  Type: Generic Access
  Description: Generic Access Profile
  Handle: 0x0001

  [Characteristic] 00002a00-0000-1000-8000-00805f9b34fb
    Description: Device Name
    Handle: 0x0003
    Capabilities: READ
    Properties: read

[Summary by Service Type]
[Generic Access] (3 characteristics)
  [READ] 00002a00-0000-1000-8000-00805f9b34fb
      (Device Name)
  [READ] 00002a01-0000-1000-8000-00805f9b34fb
      (Appearance)

[Custom Service] (2 characteristics)
  [READ | WRITE] 0000fff1-0000-1000-8000-00805f9b34fb
  [WRITE_NO_RESP] 0000fff2-0000-1000-8000-00805f9b34fb

[Quick Reference]
[Read/Write Characteristics] (1)
  - 0000fff1-0000-1000-8000-00805f9b34fb [Custom Service]

[Read-Only Characteristics] (3)
  - 00002a00-0000-1000-8000-00805f9b34fb [Generic Access] - Device Name
  - 00002a01-0000-1000-8000-00805f9b34fb [Generic Access] - Appearance
  - 00002a04-0000-1000-8000-00805f9b34fb [Generic Access] - Peripheral Preferred Connection Parameters

[Write-Only Characteristics] (1)
  - 0000fff2-0000-1000-8000-00805f9b34fb [Custom Service]
```

## Device Identification Tips

Since macOS uses UUIDs instead of MAC addresses, use the verbose scan to gather as much information as possible:

- **Device Name**: The advertised name (most reliable identifier)
- **RSSI**: Signal strength helps identify nearby devices
- **Service UUIDs**: Known service types (e.g., Heart Rate, Battery Service)
- **Manufacturer Data**: Can help identify device vendor
- **Device Number**: Reference the # from scan results for easy lookup

**Tip**: Run a verbose scan first to gather all available information, then use the short display to quickly reference devices by their number or name.

## Typical Workflow

1. **Scan for devices:**
   ```bash
   python3 gable.py --scan --verbose
   ```

2. **Connect to a device and enumerate characteristics:**
   ```bash
   python3 gable.py --mac <UUID_from_scan> --enumerate
   ```
   This shows all readable/writeable characteristics organized by capability:
   - Read/Write (both capabilities)
   - Read-Only
   - Write-Only

3. **Read characteristics (in interactive mode):**
   ```bash
   python3 gable.py --interactive
   # Select option 3 to connect
   # Select option 4 to enumerate
   # Select option 5 to read
   #   - Enter specific UUID to read one characteristic
   #   - Enter * to read all readable characteristics
   ```

4. **Fuzz characteristics for security testing:**
   
   **Option A - Interactive Mode:**
   ```bash
   python3 gable.py --interactive
   # Option 7: Fuzz a specific characteristic (targeted)
   # Option 8: Fuzz all writable characteristics (comprehensive)
   # Option 9: Write-all/read-all (state testing)
   ```
   
   **Option B - CLI Mode:**
   ```bash
   # Target a specific characteristic
   python3 gable.py --mac <UUID> --fuzz-char <CHAR_UUID> --iterations 10000
   
   # Fuzz all writable characteristics
   python3 gable.py --mac <UUID> --fuzz-all --iterations 5000
   
   # Write-all/read-all comprehensive fuzzing
   python3 gable.py --mac <UUID> --fuzz-write-read-all --iterations 1000
   ```

5. **Write to a characteristic:**
   Use interactive mode option 6 with hex data input.

## Interactive Mode Features

The interactive mode provides a user-friendly menu interface with these enhancements:

- **Context-aware menu**: Options change based on connection status
- **Connection indicator**: Shows connected device UUID in menu header
- **Smart prompt**: Changes from `>` to `connected>` when connected
- **Protected operations**: Read/write/enumerate options only appear when connected
- **Real-time feedback**: Clear messages for all operations

**Before connection:**
```
[Menu - Not Connected]
1. Scan for BLE devices (short)
2. Scan for BLE devices (verbose)
3. Connect to device by UUID
0. Exit

> 
```

**After connection:**
```
[Menu - Connected to 12345678-ABCD-1234-ABCD-123456789ABC]
1. Scan for BLE devices (short)
2. Scan for BLE devices (verbose)
3. Disconnect
4. Enumerate characteristics
5. Read characteristic
6. Write characteristic
7. Fuzz single characteristic
8. Fuzz all writable characteristics
9. Fuzz write-all/read-all
0. Exit

connected> 
```

## Reading Characteristics

### Read All Characteristics

Use the wildcard `*` to automatically read all readable characteristics:

```
connected> 5
Enter characteristic UUID (or * for all): *

[*] Reading all characteristics...
================================================================================

[Service: Generic Access]
  UUID: 00001800-0000-1000-8000-00805f9b34fb

  [Reading] 00002a00-0000-1000-8000-00805f9b34fb
    Description: Device Name
    Success! Read 10 bytes:
    4d 79 20 44 65 76 69 63 65 00                    |My Device.|
    UTF-8: My Device

  [Reading] 00002a01-0000-1000-8000-00805f9b34fb
    Description: Appearance
    Success! Read 2 bytes:
    00 00                                            |..|

[Service: Device Information]
  UUID: 0000180a-0000-1000-8000-00805f9b34fb

  [Reading] 00002a29-0000-1000-8000-00805f9b34fb
    Description: Manufacturer Name String
    Success! Read 8 bytes:
    41 63 6d 65 20 49 6e 63                          |Acme Inc|
    UTF-8: Acme Inc

================================================================================
[Summary] Successfully read 15 characteristic(s)
          Failed to read 2 characteristic(s)
================================================================================
```

This feature is useful for quickly dumping all readable data from a device during reconnaissance.

## Fuzzing Modes

GaBL-E provides three fuzzing modes for comprehensive security testing. All modes support keyboard interrupt (Ctrl+C) to stop fuzzing gracefully.

### Verbose Fuzzing Output

All fuzzing modes support verbose output that displays written and read data in hexdump format with ASCII representation for each iteration. This is useful for:
- Debugging fuzzing behavior
- Understanding device responses to specific payloads
- Identifying patterns in read/write operations
- Detailed analysis of small iteration counts

**CLI Usage:**
```bash
# Enable verbose output with --verbose-fuzz flag
python3 gable.py --mac <UUID> --fuzz-char <CHAR_UUID> --iterations 50 --verbose-fuzz --read-after-write
```

**Interactive Mode:**
All fuzzing options prompt: `Verbose output (show data for each iteration)? (y/n, default=n):`

**Example Verbose Output:**
```
[Iteration 1] Writing 12 bytes:
    48 65 6c 6c 6f 20 57 6f 72 6c 64 21                |Hello World!|
[Iteration 1] Read 12 bytes:
    48 65 6c 6c 6f 20 57 6f 72 6c 64 21                |Hello World!|

[Iteration 2] Writing 8 bytes:
    ff ff ff ff ff ff ff ff                             |........|
[Iteration 2] Read 8 bytes:
    00 00 00 00 00 00 00 00                             |........|
    [!] Value differs from written data

[Iteration 3] Writing 16 bytes:
    aa 55 aa 55 aa 55 aa 55 aa 55 aa 55 aa 55 aa 55    |.U.U.U.U.U.U.U.U|
[Iteration 3] Read 16 bytes:
    aa 55 aa 55 aa 55 aa 55 aa 55 aa 55 aa 55 aa 55    |.U.U.U.U.U.U.U.U|
```

**Note:** Verbose mode significantly slows down fuzzing due to console output. Use with small iteration counts (50-100) for analysis, not for high-speed fuzzing.

### 1. Single Characteristic Fuzzing

Target a specific writable characteristic with configurable iterations.

**CLI Usage:**
```bash
# Fuzz a specific characteristic with default 10,000 iterations
python3 gable.py --mac <UUID> --fuzz-char 0000fff1-0000-1000-8000-00805f9b34fb

# Custom iteration count
python3 gable.py --mac <UUID> --fuzz-char 0000fff1-0000-1000-8000-00805f9b34fb --iterations 5000

# Verbose output to see each write/read (use with small iteration counts)
python3 gable.py --mac <UUID> --fuzz-char 0000fff1-0000-1000-8000-00805f9b34fb --iterations 50 --verbose-fuzz

# Read after each write (for read/write characteristics)
python3 gable.py --mac <UUID> --fuzz-char 0000fff1-0000-1000-8000-00805f9b34fb --read-after-write --verbose-fuzz --iterations 100
```

**Interactive Mode:**
```
connected> 7
Enter characteristic UUID to fuzz: 0000fff1-0000-1000-8000-00805f9b34fb
Number of iterations (default=10000): 5000
Read after write? (y/n, default=n): n
Verbose output (show data for each iteration)? (y/n, default=n): n

[*] Starting fuzzing on characteristic 0000fff1-0000-1000-8000-00805f9b34fb
[*] Iterations: 5000
[*] Verbose: False
[*] Press Ctrl+C to stop
================================================================================
[*] Progress: 100/5000 | Success: 100 | Failed: 0 | Rate: 125.3 iter/sec
[*] Progress: 200/5000 | Success: 200 | Failed: 0 | Rate: 138.7 iter/sec
...
[*] Progress: 5000/5000 | Success: 5000 | Failed: 0 | Rate: 142.1 iter/sec

================================================================================
[Fuzzing Summary]
================================================================================
Characteristic: 0000fff1-0000-1000-8000-00805f9b34fb
Total Iterations: 5000
Successful: 5000
Failed: 0
Time Elapsed: 35.18 seconds
Average Rate: 142.1 iterations/sec
================================================================================
```

### 2. Fuzz All Writable Characteristics

Automatically discover and fuzz all writable characteristics sequentially.

**CLI Usage:**
```bash
# Fuzz all writable characteristics (10,000 iterations each)
python3 gable.py --mac <UUID> --fuzz-all

# Custom iterations with read-after-write and verbose output
python3 gable.py --mac <UUID> --fuzz-all --iterations 100 --read-after-write --verbose-fuzz
```

**Interactive Mode:**
```
connected> 8
Number of iterations per characteristic (default=10000): 1000
Read after write for read/write characteristics? (y/n, default=y): y
Verbose output (show data for each iteration)? (y/n, default=n): n

[*] Collecting writable characteristics...
[*] Found 2 read/write characteristics
[*] Found 1 write-only characteristics
[*] Total: 3 characteristics to fuzz
[*] 1000 iterations per characteristic
[*] Total operations: 3000
[*] Press Ctrl+C to stop
================================================================================

[*] Fuzzing characteristic 1/3: 0000fff1-0000-1000-8000-00805f9b34fb
    Progress: 1000/1000 | Rate: 145.2 iter/sec
    Completed: 1000 successful, 0 failed (6.89s)

[*] Fuzzing characteristic 2/3: 0000fff2-0000-1000-8000-00805f9b34fb
    Progress: 1000/1000 | Rate: 148.7 iter/sec
    Completed: 1000 successful, 0 failed (6.72s)

[*] Fuzzing characteristic 3/3: 0000fff3-0000-1000-8000-00805f9b34fb
    Progress: 1000/1000 | Rate: 143.1 iter/sec
    Completed: 1000 successful, 0 failed (6.99s)

================================================================================
[Overall Fuzzing Summary]
================================================================================
Characteristics Fuzzed: 3
Total Iterations: 3000
Successful: 3000
Failed: 0
Time Elapsed: 20.60 seconds
Average Rate: 145.6 iterations/sec
================================================================================
```

### 3. Write-All/Read-All Fuzzing

Write fuzz data to all writable characteristics and read all readable characteristics on each iteration. This mode is useful for:
- Discovering state-dependent behaviors
- Finding interactions between characteristics
- Comprehensive device state testing

**CLI Usage:**
```bash
# Write-all/read-all fuzzing
python3 gable.py --mac <UUID> --fuzz-write-read-all --iterations 1000

# With verbose output to see all writes and reads per iteration
python3 gable.py --mac <UUID> --fuzz-write-read-all --iterations 10 --verbose-fuzz
```

**Interactive Mode:**
```
connected> 9
Number of iterations (default=10000): 1000
Verbose output (show data for each iteration)? (y/n, default=n): n

[*] Collecting characteristics...
[*] Found 3 writable characteristics
[*] Found 8 readable characteristics
[*] Iterations: 1000
[*] Each iteration: write 3 + read 8 characteristics
[*] Press Ctrl+C to stop
================================================================================
[*] Iteration 100/1000 | Writes: 300 | Reads: 800 | Rate: 95.2 iter/sec
[*] Iteration 200/1000 | Writes: 600 | Reads: 1600 | Rate: 98.7 iter/sec
...
[*] Iteration 1000/1000 | Writes: 3000 | Reads: 8000 | Rate: 101.3 iter/sec

================================================================================
[Write-All/Read-All Fuzzing Summary]
================================================================================
Iterations Completed: 1000
Writable Characteristics: 3
Readable Characteristics: 8
Successful Writes: 3000
Failed Writes: 0
Successful Reads: 8000
Failed Reads: 0
Time Elapsed: 9.87 seconds
Average Rate: 101.3 iterations/sec
================================================================================
```

### Fuzz Data Patterns

GaBL-E generates various data patterns to maximize fuzzing effectiveness:
- **Random bytes**: Random values (0x00-0xFF)
- **All zeros**: `0x00` repeated
- **All ones**: `0xFF` repeated
- **Alternating pattern**: `0xAA` and `0x55` alternating
- **Incrementing bytes**: 0x00, 0x01, 0x02, ..., 0xFF
- **Decrementing bytes**: 0xFF, 0xFE, 0xFD, ..., 0x00
- **Random ASCII**: Printable ASCII characters (0x20-0x7E)
- **Boundary values**: Mix of 0x00, 0xFF, 0x7F, 0x80

Each iteration randomly selects a pattern and length (1-255 bytes) to maximize coverage.

## Advanced Fuzzing Strategies

GaBL-E includes multiple specialized fuzzing strategies designed to exploit different types of vulnerabilities:

### Strategy Selection

**CLI:** Use `--strategy <name>` flag
**Interactive:** Select from menu when starting fuzzing (options 7, 8, or 9)

Available strategies:
1. **basic** - Random patterns (default)
2. **cmd_injection** - Command injection attempts
3. **format_string** - Format string attacks
4. **length** - Length-based attacks
5. **tlv** - Malformed TLV structures
6. **markov** - Markov chain stochastic data
7. **all** - Random mix of all strategies

### 1. Command Injection Strategy (`cmd_injection`)

Attempts to exploit command injection vulnerabilities by sending payloads with various shell command wrappers.

**Payloads include:**
- Plain commands: `reboot`, `halt`, `shutdown`, `cat /etc/passwd`
- Backtick execution: `` `reboot` ``
- Command substitution: `$(reboot)`, `$((reboot))`
- Shell separators: `;reboot;`, `|reboot`, `||reboot`, `&&reboot`
- Newline injection: `\nreboot\n`, `%0areboot%0a`
- IFS injection: `${IFS}reboot`
- Multiple attempts: `` `reboot`||`reboot` ``

**Example:**
```bash
python3 gable.py --mac <UUID> --fuzz-char <CHAR_UUID> --strategy cmd_injection --iterations 1000
```

**Use case:** Test if the device executes commands from BLE input, common in embedded Linux/RTOS devices with shell interpreters.

### 2. Format String Strategy (`format_string`)

Generates format string attack payloads to exploit vulnerabilities in printf-style functions.

**Payloads include:**
- String specifiers: `%s%s%s`
- Hex specifiers: `%x%x%x`
- Write specifiers: `%n%n%n`
- Pointer display: `%p%p%p`
- Combined attacks: `%s%s%s%n%n%n`, `%x%x%x%n%n%n`
- Large width: `%.10000x`, `%*10000d`
- Positional arguments: `%1$s%2$s%3$s`, `%$100$x`
- Prefixed attacks: `AAAA%x%x%x%n`

**Example:**
```bash
python3 gable.py --mac <UUID> --fuzz-char <CHAR_UUID> --strategy format_string --iterations 500 --verbose-fuzz
```

**Use case:** Exploit printf-style vulnerabilities to read/write arbitrary memory locations.

### 3. Length Attack Strategy (`length`)

Sends payloads of extreme lengths to trigger buffer overflows, integer overflows, or memory exhaustion.

**Payload lengths:**
- 255 bytes (max standard BLE packet)
- 256 bytes (just over limit)
- 512, 1024, 4096, 8192 bytes (progressively larger)
- 32767 bytes (signed int16 max)
- 65535 bytes (unsigned int16 max)
- Random large sizes (256-1000 bytes)
- Powers of 2 (256, 512, 1024, 2048, 4096)

**Example:**
```bash
python3 gable.py --mac <UUID> --fuzz-char <CHAR_UUID> --strategy length --iterations 100
```

**Use case:** Detect buffer overflow vulnerabilities, improper bounds checking, or memory allocation issues.

**Warning:** Large payloads may cause device crashes or memory errors. Use with caution.

### 4. TLV Attack Strategy (`tlv`)

Generates malformed Type-Length-Value (TLV) structures commonly used in BLE protocols.

**Attack vectors:**
- Length mismatches (claimed length > actual data)
- Zero length fields
- Negative length values (when interpreted as signed)
- Nested TLV structures (1-5 levels deep with intentional mismatches)
- Sequential TLVs with incorrect lengths
- Huge claimed lengths with minimal data
- Overlapping TLV fields
- Multiple valid TLVs (stress testing)

**Example TLV structure:**
```
Type: 0x01, Length: 0xFF (255), Value: only 2 bytes
[01 FF 41 42]
```

**Example:**
```bash
python3 gable.py --mac <UUID> --fuzz-char <CHAR_UUID> --strategy tlv --iterations 1000 --read-after-write
```

**Use case:** Exploit parsing vulnerabilities in TLV-based protocols (common in BLE GATT, NFC, and embedded protocols).

### 5. Markov Chain Strategy (`markov`)

Generates random data following a Markov chain stochastic process with state transitions.

**States:**
- **null**: 0x00 bytes
- **max**: 0xFF bytes
- **ascii**: Printable ASCII (0x20-0x7E)
- **control**: Control characters (0x00-0x1F)
- **random**: Random bytes (0x00-0xFF)

**Transition probabilities:**
- Each state has weighted probabilities to transition to other states
- Creates realistic-looking but malformed data streams
- More sophisticated than pure random, follows patterns devices might expect

**Example:**
```bash
python3 gable.py --mac <UUID> --fuzz-all --strategy markov --iterations 5000
```

**Use case:** Generate more "intelligent" random data that mimics expected protocols while introducing anomalies. Good for stateful protocol fuzzing.

### 6. All Strategies (`all`)

Randomly selects a different strategy for each iteration, providing comprehensive coverage.

**Example:**
```bash
python3 gable.py --mac <UUID> --fuzz-write-read-all --strategy all --iterations 10000
```

**Use case:** Maximum coverage testing when you want to try all attack vectors in a single fuzzing session.

### Strategy Comparison Table

| Strategy        | Speed  | Crash Likelihood | Coverage | Best For                    |
|----------------|--------|------------------|----------|----------------------------|
| basic          | Fast   | Medium           | General  | Initial reconnaissance      |
| cmd_injection  | Fast   | Low-Medium       | Specific | Shell-enabled devices       |
| format_string  | Fast   | Medium-High      | Specific | Printf vulnerabilities      |
| length         | Slow   | High             | Specific | Buffer overflows            |
| tlv            | Fast   | Medium-High      | Specific | Protocol parsing bugs       |
| markov         | Fast   | Medium           | General  | Stateful protocols          |
| all            | Medium | High             | Maximum  | Comprehensive testing       |

### Strategy Selection Tips

1. **Start with `basic`** for initial fuzzing to understand device behavior
2. **Use `cmd_injection`** if device runs Linux/RTOS with shell access
3. **Use `format_string`** if you suspect C/C++ code with printf functions
4. **Use `length`** when testing for memory safety issues (have recovery plan!)
5. **Use `tlv`** for BLE services using structured data formats
6. **Use `markov`** for protocol-aware testing
7. **Use `all`** for final comprehensive security assessment

## Security Considerations

⚠️ **Warning**: This tool is designed for authorized security testing only. Unauthorized access to BLE devices may be illegal in your jurisdiction.

- Always obtain proper authorization before testing
- Respect privacy and security of others
- Follow responsible disclosure practices
- Comply with local laws and regulations

## Architecture

The fuzzer is built around the `BLEFuzzer` class which provides:

1. **Scanning**: Uses Bleak's `BleakScanner` to discover devices
2. **Connection**: Establishes connections using `BleakClient`
3. **Enumeration**: Iterates through GATT services and characteristics
4. **I/O Operations**: Reads and writes characteristic values

## macOS Bluetooth Permissions

On macOS, you may need to grant Bluetooth permissions to your terminal application or Python interpreter. Go to:

**System Preferences → Security & Privacy → Privacy → Bluetooth**

And ensure your terminal app has permission.

### macOS Address Format

**Important**: macOS uses UUIDs (like `12345678-ABCD-1234-ABCD-123456789ABC`) instead of traditional MAC addresses for BLE devices due to CoreBluetooth privacy restrictions.

To connect to a device, use the UUID shown in the scan results:
```bash
python3 gable.py --mac 12345678-ABCD-1234-ABCD-123456789ABC --enumerate
```

**Note**: The parameter is called `--mac` for convenience, but it expects a UUID on macOS.

## Troubleshooting

**Issue**: "No devices found"
- Ensure Bluetooth is enabled
- Check that devices are in pairing/advertising mode
- Increase scan duration

**Issue**: "Can't tell which device is which"
- Use verbose scan mode (`--verbose`) for detailed information
- Look for device names, service UUIDs, and manufacturer data
- Use RSSI to identify nearest devices
- Check if the device has a distinctive name or known service UUID

**Issue**: "Failed to connect"
- Verify the UUID is correct (copy from scan results)
- Ensure the device is still in range
- Some devices require pairing first

**Issue**: "Permission denied"
- Check macOS Bluetooth permissions
- Run with appropriate privileges if necessary

## Future Enhancements

- [ ] Advanced fuzzing modes (mutation-based, grammar-based, intelligent)
- [ ] Notification/Indication handling and monitoring
- [ ] Pairing and bonding support
- [ ] Protocol analysis and logging (PCAP export)
- [ ] Replay attacks from captured data
- [ ] Timing analysis and race condition testing
- [ ] Export results to various formats (JSON, CSV, HTML reports)
- [ ] Crash detection and device state monitoring

## License

This tool is provided for educational and authorized security testing purposes only.
