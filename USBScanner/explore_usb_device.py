##############
### Tool to explore USB Interfaces of devices
##
## Gabriel Gonzalez Garcia 2025 
## www.gabrielcybersecurity.com
##
########
##  BSD 3-Clause License
##
## Copyright (c) 2025, Gabriel Gonzalez Garcia - www.gabrielcybersecurity.com
#
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions are met:
##
## 1. Redistributions of source code must retain the above copyright notice, this
##    list of conditions and the following disclaimer.
##
## 2. Redistributions in binary form must reproduce the above copyright notice,
##    this list of conditions and the following disclaimer in the documentation
##    and/or other materials provided with the distribution.
##
## 3. Neither the name of the copyright holder nor the names of its
##    contributors may be used to endorse or promote products derived from
##    this software without specific prior written permission.
##
## THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
## AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
## DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
## FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
## DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
## SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
## CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
## OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
## OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import usb.core
import usb.util
import sys
import argparse
import time
import os
import random
import datetime
import stat

class USBLogger:
    def __init__(self, base_folder=None):
        if base_folder is None or base_folder == '':
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            base_folder = f"session_{timestamp}"
        
        self.base_folder = base_folder
        os.makedirs(base_folder, exist_ok=True)
        
        # File paths
        self.commands_all_bin = os.path.join(base_folder, "commands-all.bin")
        self.commands_all_txt = os.path.join(base_folder, "commands-all.txt")
        self.commands_acked_bin = os.path.join(base_folder, "commands-acked.bin")
        self.commands_acked_txt = os.path.join(base_folder, "commands-acked.txt")
        self.cmd_resp_bin = os.path.join(base_folder, "cmd-resp.bin")
        self.cmd_resp_txt = os.path.join(base_folder, "cmd-resp.txt")
        self.responses_bin = os.path.join(base_folder, "responses.bin")
        self.responses_txt = os.path.join(base_folder, "responses.txt")
        self.traffic_bin = os.path.join(base_folder, "traffic.bin")
        self.traffic_txt = os.path.join(base_folder, "traffic.txt")
        
        # Initialize files
        for f in [self.commands_all_bin, self.commands_all_txt, self.commands_acked_bin,
                  self.commands_acked_txt, self.cmd_resp_bin, self.cmd_resp_txt,
                  self.responses_bin, self.responses_txt, self.traffic_bin, self.traffic_txt]:
            open(f, 'wb' if f.endswith('.bin') else 'w').close()
        
        # If running as root, change ownership to the script owner
        if os.geteuid() == 0:
            try:
                # Get the script file's owner
                script_stat = os.stat(__file__)
                script_uid = script_stat.st_uid
                script_gid = script_stat.st_gid
                
                # Change ownership of directory
                os.chown(base_folder, script_uid, script_gid)
                
                # Change ownership of all files
                for f in [self.commands_all_bin, self.commands_all_txt, self.commands_acked_bin,
                          self.commands_acked_txt, self.cmd_resp_bin, self.cmd_resp_txt,
                          self.responses_bin, self.responses_txt, self.traffic_bin, self.traffic_txt]:
                    os.chown(f, script_uid, script_gid)
            except (OSError, PermissionError) as e:
                print(f"Warning: Could not change ownership of log files: {e}")
        
        # Track last command for pairing with response
        self.last_cmd = None
        
        print(f"Logging enabled: {self.base_folder}")
    
    def log_command(self, cmd_bytes):
        """Log a command"""
        self.last_cmd = cmd_bytes
        
        # Commands-all binary file
        with open(self.commands_all_bin, 'ab') as f:
            f.write(cmd_bytes)
        
        # Commands-all text file (hex)
        with open(self.commands_all_txt, 'a') as f:
            hex_str = ' '.join([f'{x:02x}' for x in cmd_bytes])
            f.write(hex_str + '\n')
        
        # Traffic binary
        with open(self.traffic_bin, 'ab') as f:
            f.write(cmd_bytes)
        
        # Traffic text
        with open(self.traffic_txt, 'a') as f:
            hex_str = ' '.join([f'{x:02x}' for x in cmd_bytes])
            f.write(f"CMD: {hex_str}\n")
    
    def log_response(self, resp_bytes):
        """Log a response"""
        # Responses binary file
        with open(self.responses_bin, 'ab') as f:
            f.write(resp_bytes)
        
        # Responses text file (hex)
        with open(self.responses_txt, 'a') as f:
            hex_str = ' '.join([f'{x:02x}' for x in resp_bytes])
            f.write(hex_str + '\n')
        
        # Traffic binary
        with open(self.traffic_bin, 'ab') as f:
            f.write(resp_bytes)
        
        # Traffic text
        with open(self.traffic_txt, 'a') as f:
            hex_str = ' '.join([f'{x:02x}' for x in resp_bytes])
            f.write(f"RSP: {hex_str}\n")
        
        # Commands-acked (only commands that got responses)
        if self.last_cmd:
            with open(self.commands_acked_bin, 'ab') as f:
                f.write(self.last_cmd)
            
            with open(self.commands_acked_txt, 'a') as f:
                hex_str = ' '.join([f'{x:02x}' for x in self.last_cmd])
                f.write(hex_str + '\n')
        
        # Cmd-resp (command followed by response)
        if self.last_cmd:
            # Binary: command then response
            with open(self.cmd_resp_bin, 'ab') as f:
                f.write(self.last_cmd)
                f.write(resp_bytes)
            
            # Text: CMD line then RSP line
            with open(self.cmd_resp_txt, 'a') as f:
                cmd_hex = ' '.join([f'{x:02x}' for x in self.last_cmd])
                resp_hex = ' '.join([f'{x:02x}' for x in resp_bytes])
                f.write(f"CMD: {cmd_hex}\n")
                f.write(f"RSP: {resp_hex}\n")

def enumerate_endpoints(dev, vid, pid):
    print(f"Device found: Vendor ID 0x{vid:04x}, Product ID 0x{pid:04x}")
    print("-" * 60)

    # Iterate through all configurations
    for cfg in dev:
        print(f"Configuration: {cfg.bConfigurationValue}")
        
        # Iterate through all interfaces
        for intf in cfg:
            print(f"  Interface: {intf.bInterfaceNumber}, Alternate Setting: {intf.bAlternateSetting}")
            
            # Iterate through all endpoints
            for ep in intf:
                print(f"    Endpoint Address: 0x{ep.bEndpointAddress:02x}")
                
                # Check direction
                if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_OUT:
                    direction = "OUT"
                else:
                    direction = "IN"
                print(f"      Direction: {direction}")
                
                # Check type
                type_val = usb.util.endpoint_type(ep.bmAttributes)
                if type_val == usb.util.ENDPOINT_TYPE_BULK:
                    ep_type = "BULK"
                elif type_val == usb.util.ENDPOINT_TYPE_INTR:
                    ep_type = "INTERRUPT"
                elif type_val == usb.util.ENDPOINT_TYPE_ISO:
                    ep_type = "ISOCHRONOUS"
                else:
                    ep_type = "CONTROL"
                print(f"      Type: {ep_type}")
                
                print(f"      Attributes: 0x{ep.bmAttributes:02x}")
                print(f"      Max Packet Size: {ep.wMaxPacketSize}")
                print(f"      Interval: {ep.bInterval}")
                print("")

def get_descriptors(dev, max_index=255, bruteforce=False, logger=None):
    """
    Enumerate USB descriptors by sending GET_DESCRIPTOR requests with different indexes.
    
    Standard descriptor types:
    - 0x01: DEVICE
    - 0x02: CONFIGURATION
    - 0x03: STRING
    - 0x04: INTERFACE
    - 0x05: ENDPOINT
    - 0x06: DEVICE_QUALIFIER
    - 0x07: OTHER_SPEED_CONFIGURATION
    - 0x21: HID
    - 0x22: REPORT
    - 0x23: PHYSICAL
    
    Args:
        dev: USB device object
        max_index: Maximum index to try for each descriptor type (0-255)
        bruteforce: If True, try all descriptor types 0x00-0xFF instead of just standard ones
        logger: USBLogger instance for logging descriptor requests/responses
    """
    if bruteforce:
        print(f"Enumerating USB descriptors in BRUTE-FORCE mode (types 0x00-0xFF, indexes 0-{max_index})...")
    else:
        print(f"Enumerating USB descriptors (indexes 0-{max_index})...")
    print("=" * 80)
    
    # Standard descriptor type names
    descriptor_types = {
        0x01: "DEVICE",
        0x02: "CONFIGURATION",
        0x03: "STRING",
        0x04: "INTERFACE",
        0x05: "ENDPOINT",
        0x06: "DEVICE_QUALIFIER",
        0x07: "OTHER_SPEED_CONFIGURATION",
        0x21: "HID",
        0x22: "REPORT",
        0x23: "PHYSICAL"
    }
    
    found_count = 0
    
    # Determine which descriptor types to try
    if bruteforce:
        desc_types = range(0x00, 0x100)  # All possible byte values
        print("Testing all descriptor types 0x00-0xFF...")
    else:
        desc_types = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x21, 0x22, 0x23]
    
    # Try different descriptor types
    for desc_type in desc_types:
        type_name = descriptor_types.get(desc_type, f"UNKNOWN_0x{desc_type:02x}")
        print(f"\n--- Descriptor Type: 0x{desc_type:02x} ({type_name}) ---")
        
        for index in range(max_index + 1):
            try:
                # GET_DESCRIPTOR request
                # bmRequestType = 0x80 (Device-to-Host, Standard, Device)
                # bRequest = 0x06 (GET_DESCRIPTOR)
                # wValue = (desc_type << 8) | index
                # wIndex = 0 (or language ID for strings)
                # wLength = 255 (max size to read)
                
                wValue = (desc_type << 8) | index
                wIndex = 0
                
                # For string descriptors, try with language ID 0x0409 (English US) if index > 0
                if desc_type == 0x03 and index > 0:
                    wIndex = 0x0409
                
                # Log the control request as a "command"
                if logger:
                    # Format: bmRequestType bRequest wValueHi wValueLo wIndexHi wIndexLo wLength
                    cmd_bytes = bytes([0x80, 0x06, (wValue >> 8) & 0xFF, wValue & 0xFF, 
                                      (wIndex >> 8) & 0xFF, wIndex & 0xFF, 0xFF])
                    logger.log_command(cmd_bytes)
                
                data = dev.ctrl_transfer(
                    bmRequestType=0x80,  # IN, Standard, Device
                    bRequest=0x06,        # GET_DESCRIPTOR
                    wValue=wValue,
                    wIndex=wIndex,
                    data_or_wLength=255
                )
                
                if len(data) > 0:
                    found_count += 1
                    
                    # Log the response
                    if logger:
                        logger.log_response(bytes(data))
                    
                    hex_data = ' '.join([f'{x:02x}' for x in data])
                    
                    # Try to decode string descriptors
                    if desc_type == 0x03 and len(data) >= 2:
                        try:
                            # String descriptors: first byte is length, second is type
                            string_len = data[0]
                            if data[1] == 0x03 and string_len <= len(data):
                                # UTF-16LE encoded string
                                string_data = bytes(data[2:string_len]).decode('utf-16-le', errors='replace')
                                print(f"  Index {index:3d}: {hex_data[:60]}{'...' if len(hex_data) > 60 else ''}")
                                print(f"             String: \"{string_data}\"")
                            else:
                                print(f"  Index {index:3d}: {hex_data[:60]}{'...' if len(hex_data) > 60 else ''}")
                        except:
                            print(f"  Index {index:3d}: {hex_data[:60]}{'...' if len(hex_data) > 60 else ''}")
                    else:
                        # Show first 60 chars of hex data
                        print(f"  Index {index:3d}: {hex_data[:60]}{'...' if len(hex_data) > 60 else ''}")
                        
            except usb.core.USBError as e:
                # Most indexes will fail with PIPE error or timeout
                pass
            except Exception as e:
                # Catch any other errors
                pass
    
    print("\n" + "=" * 80)
    print(f"Found {found_count} descriptors")
    return found_count

def bruteforce_scan(dev, max_length=None, skip_patterns=None, prefix=None, postfix=None, logger=None):
    print("Scanning device for commands (Brute-force)...")
    print("WARNING: Sending random data can have unexpected side effects.")
    if max_length:
        print(f"Will scan up to {max_length} byte(s). Press Ctrl+C to stop early.")
    else:
        print("Will scan incrementally (1 byte, 2 bytes, 3 bytes...). Press Ctrl+C to stop.")
    
    # Parse prefix/postfix
    prefix_bytes = []
    postfix_bytes = []
    if prefix:
        prefix_hex = prefix.replace(' ', '')
        prefix_bytes = [int(prefix_hex[i:i+2], 16) for i in range(0, len(prefix_hex), 2)]
        print(f"Prefix: {' '.join([f'{x:02x}' for x in prefix_bytes])}")
    if postfix:
        postfix_hex = postfix.replace(' ', '')
        postfix_bytes = [int(postfix_hex[i:i+2], 16) for i in range(0, len(postfix_hex), 2)]
        print(f"Postfix: {' '.join([f'{x:02x}' for x in postfix_bytes])}")
    
    # Parse skip patterns
    skip_rules = []
    if skip_patterns:
        for pattern in skip_patterns:
            pattern = pattern.strip()
            if pattern.startswith('*') and pattern.endswith('*'):
                # Contains pattern
                hex_val = pattern[1:-1]
                byte_val = int(hex_val, 16)
                skip_rules.append(('contains', byte_val))
                print(f"Skip rule: Any command containing 0x{byte_val:02x}")
            elif pattern.startswith('*'):
                # Ends with pattern
                hex_val = pattern[1:]
                byte_val = int(hex_val, 16)
                skip_rules.append(('ends_with', byte_val))
                print(f"Skip rule: Any command ending with 0x{byte_val:02x}")
            elif pattern.endswith('*'):
                # Starts with pattern
                hex_val = pattern[:-1]
                byte_val = int(hex_val, 16)
                skip_rules.append(('starts_with', byte_val))
                print(f"Skip rule: Any command starting with 0x{byte_val:02x}")
            else:
                # Exact single byte match
                byte_val = int(pattern, 16)
                skip_rules.append(('exact', byte_val))
                print(f"Skip rule: Single-byte command 0x{byte_val:02x}")
    
    def should_skip(cmd_bytes):
        """Check if command should be skipped based on skip rules"""
        for rule_type, byte_val in skip_rules:
            if rule_type == 'exact':
                # Only skip if it's a single byte command matching the value
                if len(cmd_bytes) == 1 and cmd_bytes[0] == byte_val:
                    return True
            elif rule_type == 'starts_with':
                if len(cmd_bytes) > 0 and cmd_bytes[0] == byte_val:
                    return True
            elif rule_type == 'ends_with':
                if len(cmd_bytes) > 0 and cmd_bytes[-1] == byte_val:
                    return True
            elif rule_type == 'contains':
                if byte_val in cmd_bytes:
                    return True
        return False

    # Set active config
    try:
        dev.set_configuration()
    except usb.core.USBError:
        pass
    
    cfg = dev.get_active_configuration()
    
    # We need an interface with both IN and OUT endpoints
    target_intf = None
    ep_in = None
    ep_out = None
    
    for intf in cfg:
        # Check for kernel driver
        if dev.is_kernel_driver_active(intf.bInterfaceNumber):
            try:
                dev.detach_kernel_driver(intf.bInterfaceNumber)
            except usb.core.USBError:
                pass
                
        try:
            usb.util.claim_interface(dev, intf.bInterfaceNumber)
        except usb.core.USBError:
            continue
            
        # Look for endpoints - find first IN and first OUT
        temp_in = None
        temp_out = None
        for ep in intf:
            if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN:
                if temp_in is None:  # Take first IN endpoint
                    temp_in = ep
            else:
                if temp_out is None:  # Take first OUT endpoint
                    temp_out = ep
        
        if temp_in and temp_out:
            target_intf = intf
            ep_in = temp_in
            ep_out = temp_out
            print(f"Using Interface {intf.bInterfaceNumber}")
            print(f"  OUT Endpoint: 0x{ep_out.bEndpointAddress:02x}")
            print(f"  IN Endpoint:  0x{ep_in.bEndpointAddress:02x}")
            break
        else:
            try:
                usb.util.release_interface(dev, intf.bInterfaceNumber)
            except usb.core.USBError:
                pass
            
    if not target_intf:
        print("No suitable interface found (need both IN and OUT endpoints).")
        return

    def scan_n_bytes(n):
        """Scan all combinations of n bytes"""
        print(f"\n--- Starting {n}-Byte Scan ---")
        total_combinations = 256 ** n
        print(f"Total combinations: {total_combinations:,}")
        
        counter = [0]  # Use list to allow modification in nested function
        
        # Generate all combinations recursively
        def generate_combinations(depth, current):
            if depth == n:
                cmd = bytes(prefix_bytes + current + postfix_bytes)
                counter[0] += 1
                
                # Print progress before checking skip (to show all progress)
                #if counter[0] % 256 == 0 or counter[0] == 1:
                progress = (counter[0] / total_combinations) * 100
                hex_bytes = ' '.join([f'0x{x:02x}' for x in current])
                print(f"Progress: {progress:.2f}% - Testing: [{hex_bytes}]" + " " * 20, end='\r')
                #    sys.stdout.flush()  # Force immediate display
                
                # Check if this command should be skipped
                if should_skip(current):
                    return
                
                try:
                    if logger:
                        logger.log_command(cmd)
                    dev.write(ep_out, cmd)
                    time.sleep(0.01)  # Small delay to avoid overwhelming device
                    try:
                        # Short timeout for scan
                        data = dev.read(ep_in, ep_in.wMaxPacketSize, 50)
                        if logger:
                            logger.log_response(bytes(data))
                        hex_cmd = ' '.join([f'{x:02x}' for x in cmd])
                        hex_data = ' '.join([f'{x:02x}' for x in data])
                        ascii_data = ''.join([chr(x) if 32 <= x <= 126 else '.' for x in data])
                        print(f"\n[MATCH] Command {hex_cmd} -> Response: {hex_data}")
                        print(f"        ASCII: {ascii_data}")
                    except usb.core.USBError:
                        # Timeout is expected for invalid commands
                        pass
                except usb.core.USBError as e:
                    hex_cmd = ' '.join([f'{x:02x}' for x in cmd])
                    print(f"\nWrite error on {hex_cmd}: {e}")
                return
            
            for i in range(256):
                generate_combinations(depth + 1, current + [i])
        
        generate_combinations(0, [])
        print()  # Final newline after progress
        print(f"{n}-Byte scan completed. Tested {counter[0]:,} combinations.")

    try:
        byte_length = 1
        while True:
            if max_length and byte_length > max_length:
                print(f"\nReached maximum byte length: {max_length}")
                break
            
            scan_n_bytes(byte_length)
            byte_length += 1

    except KeyboardInterrupt:
        print("\nScan stopped by user.")
    finally:
        if target_intf:
            usb.util.release_interface(dev, target_intf.bInterfaceNumber)

def select_device(device_id, vid_arg=None, pid_arg=None):
    """
    Select a USB device either by enumeration index or by VID/PID.
    
    Args:
        device_id: Integer device index (>0) or 0/None to use VID/PID
        vid_arg: Vendor ID string (hex format like "0x1234") or None
        pid_arg: Product ID string (hex format like "0x5678") or None
    
    Returns:
        tuple: (dev, target_vid, target_pid) where dev is the usb.core.Device object
    
    Exits with error message if device cannot be found or invalid parameters.
    """
    dev = None
    target_vid = None
    target_pid = None
    
    if device_id and device_id > 0:
        # Select by enumeration index
        print(f"Selecting device #{device_id} from enumeration list...")
        devs = usb.core.find(find_all=True)
        count = 0
        found = False
        for d in devs:
            count += 1
            if count == device_id:
                dev = d
                target_vid = d.idVendor
                target_pid = d.idProduct
                found = True
                break
        
        if not found:
            print(f"Error: Device #{device_id} not found in enumeration.")
            sys.exit(1)
            
        print(f"Selected Device: VID=0x{target_vid:04x} PID=0x{target_pid:04x}")
        try:
            manufacturer = usb.util.get_string(dev, dev.iManufacturer)
            product = usb.util.get_string(dev, dev.iProduct)
            print(f"  Manufacturer: {manufacturer}")
            print(f"  Product:      {product}")
        except (usb.core.USBError, ValueError, IndexError):
            print("  (Unable to read manufacturer/product strings)")
        print("-" * 60)
    else:
        # Select by VID/PID
        if not vid_arg or not pid_arg:
            print("Error: Either provide device index or both --vid and --pid")
            sys.exit(1)
            
        try:
            target_vid = int(vid_arg, 16)
        except ValueError:
            print("Invalid VID format. Use hex (e.g. 0x1234)")
            sys.exit(1)
            
        try:
            target_pid = int(pid_arg, 16)
        except ValueError:
            print("Invalid PID format. Use hex (e.g. 0x5678)")
            sys.exit(1)

        dev = usb.core.find(idVendor=target_vid, idProduct=target_pid)
        if dev is None:
            print(f"Device not found: Vendor ID 0x{target_vid:04x}, Product ID 0x{target_pid:04x}")
            sys.exit(1)
    
    return dev, target_vid, target_pid

def list_all_devices():
    if sys.platform != 'win32' and hasattr(os, 'geteuid') and os.geteuid() != 0:
        print("Warning: Not running as root. Some devices may not be listed.")
        print("Try running with 'sudo'.")
        
    print("Scanning for USB devices...")
    print("=" * 80)
    devs = usb.core.find(find_all=True)
    count = 0
    for dev in devs:
        count += 1
        try:
            vid = dev.idVendor
            pid = dev.idProduct
            print(f"\nDevice {count}: VID=0x{vid:04x} PID=0x{pid:04x}")
            try:
                manufacturer = usb.util.get_string(dev, dev.iManufacturer)
                product = usb.util.get_string(dev, dev.iProduct)
                print(f"  Manufacturer: {manufacturer}")
                print(f"  Product:      {product}")
            except (usb.core.USBError, ValueError, IndexError):
                print("  (Unable to read manufacturer/product strings)")
            
            # Enumerate configurations, interfaces, and endpoints
            try:
                for cfg in dev:
                    print(f"\n  Configuration {cfg.bConfigurationValue}:")
                    for intf in cfg:
                        # Get interface class information
                        class_code = intf.bInterfaceClass
                        subclass_code = intf.bInterfaceSubClass
                        protocol_code = intf.bInterfaceProtocol
                        
                        # Map common class codes to names
                        class_names = {
                            0x01: "Audio",
                            0x02: "Communications (CDC)",
                            0x03: "Human Interface Device (HID)",
                            0x05: "Physical",
                            0x06: "Image",
                            0x07: "Printer",
                            0x08: "Mass Storage",
                            0x09: "Hub",
                            0x0A: "CDC-Data",
                            0x0B: "Smart Card",
                            0x0D: "Content Security",
                            0x0E: "Video",
                            0x0F: "Personal Healthcare",
                            0x10: "Audio/Video",
                            0xDC: "Diagnostic",
                            0xE0: "Wireless Controller",
                            0xEF: "Miscellaneous",
                            0xFE: "Application Specific",
                            0xFF: "Vendor Specific"
                        }
                        class_name = class_names.get(class_code, "Unknown")
                        
                        print(f"    Interface {intf.bInterfaceNumber} (Alt {intf.bAlternateSetting}):")
                        print(f"      Class: 0x{class_code:02x} ({class_name})")
                        print(f"      SubClass: 0x{subclass_code:02x}, Protocol: 0x{protocol_code:02x}")
                        
                        # List endpoints
                        endpoints = list(intf)
                        if len(endpoints) > 0:
                            print(f"      Endpoints:")
                            for ep in endpoints:
                                ep_addr = ep.bEndpointAddress
                                
                                # Determine direction
                                if usb.util.endpoint_direction(ep_addr) == usb.util.ENDPOINT_OUT:
                                    direction = "OUT"
                                else:
                                    direction = "IN"
                                
                                # Determine type
                                ep_type_val = usb.util.endpoint_type(ep.bmAttributes)
                                if ep_type_val == usb.util.ENDPOINT_TYPE_BULK:
                                    ep_type = "BULK"
                                elif ep_type_val == usb.util.ENDPOINT_TYPE_INTR:
                                    ep_type = "INTERRUPT"
                                elif ep_type_val == usb.util.ENDPOINT_TYPE_ISO:
                                    ep_type = "ISOCHRONOUS"
                                else:
                                    ep_type = "CONTROL"
                                
                                print(f"        0x{ep_addr:02x}: {direction:3s} {ep_type:11s} (MaxPacket: {ep.wMaxPacketSize}, Interval: {ep.bInterval})")
                        else:
                            print(f"      No endpoints")
            except Exception as e:
                print(f"  Error reading device configuration: {e}")
                
        except Exception as e:
            print(f"  Error reading device info: {e}")
        print("=" * 80)
    
    if count == 0:
        print("No USB devices found.")

def send_single_command(dev, command_hex, logger=None):
    """
    Send a single command in hex format to the USB device and display response.
    
    Args:
        dev: USB device object
        command_hex: Command in hex format (e.g., "AA BB CC" or "AABBCC")
        logger: Optional USBLogger instance for logging
    """
    print(f"Sending single command: {command_hex}")
    print("=" * 80)
    
    # Parse hex command
    command_hex = command_hex.replace(' ', '').replace(',', '')
    if len(command_hex) % 2 != 0:
        print("Error: Hex string must have even number of characters")
        return
    
    try:
        cmd_bytes = bytes([int(command_hex[i:i+2], 16) for i in range(0, len(command_hex), 2)])
    except ValueError as e:
        print(f"Error: Invalid hex format - {e}")
        return
    
    hex_cmd = ' '.join([f'{x:02x}' for x in cmd_bytes])
    print(f"Command bytes: {hex_cmd}")
    print(f"Command length: {len(cmd_bytes)} bytes")
    print("-" * 80)
    
    # Set active config
    try:
        dev.set_configuration()
    except usb.core.USBError:
        pass
    
    cfg = dev.get_active_configuration()
    
    # Scan all interfaces and collect endpoint information
    print("Scanning device interfaces and endpoints...")
    available_interfaces = []
    
    for intf in cfg:
        intf_info = {
            'interface': intf,
            'number': intf.bInterfaceNumber,
            'endpoints_in': [],
            'endpoints_out': []
        }
        
        for ep in intf:
            if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN:
                intf_info['endpoints_in'].append(ep)
            else:
                intf_info['endpoints_out'].append(ep)
        
        available_interfaces.append(intf_info)
        print(f"  Interface {intf.bInterfaceNumber}: "
              f"{len(intf_info['endpoints_out'])} OUT endpoint(s), "
              f"{len(intf_info['endpoints_in'])} IN endpoint(s)")
    
    print("-" * 80)
    
    # Find interface with both IN and OUT endpoints
    target_intf = None
    ep_in = None
    ep_out = None
    
    for intf_info in available_interfaces:
        intf = intf_info['interface']
        
        # Check for kernel driver
        if dev.is_kernel_driver_active(intf.bInterfaceNumber):
            try:
                dev.detach_kernel_driver(intf.bInterfaceNumber)
                print(f"Detached kernel driver from interface {intf.bInterfaceNumber}")
            except usb.core.USBError as e:
                print(f"Could not detach kernel driver from interface {intf.bInterfaceNumber}: {e}")
                
        try:
            usb.util.claim_interface(dev, intf.bInterfaceNumber)
        except usb.core.USBError as e:
            print(f"Could not claim interface {intf.bInterfaceNumber}: {e}")
            continue
        
        # Prefer interfaces with both IN and OUT endpoints
        if intf_info['endpoints_out'] and intf_info['endpoints_in']:
            target_intf = intf
            ep_out = intf_info['endpoints_out'][0]
            ep_in = intf_info['endpoints_in'][0]
            print(f"\nUsing Interface {intf.bInterfaceNumber}")
            print(f"  OUT Endpoint: 0x{ep_out.bEndpointAddress:02x} "
                  f"(Type: {_get_endpoint_type_name(ep_out.bmAttributes)}, "
                  f"MaxPacket: {ep_out.wMaxPacketSize})")
            print(f"  IN Endpoint:  0x{ep_in.bEndpointAddress:02x} "
                  f"(Type: {_get_endpoint_type_name(ep_in.bmAttributes)}, "
                  f"MaxPacket: {ep_in.wMaxPacketSize})")
            print("-" * 80)
            break
        else:
            try:
                usb.util.release_interface(dev, intf.bInterfaceNumber)
            except usb.core.USBError:
                pass
            
    if not target_intf:
        print("\nError: No suitable interface found with both IN and OUT endpoints.")
        print("\nAvailable endpoint configuration:")
        for intf_info in available_interfaces:
            print(f"  Interface {intf_info['number']}:")
            if intf_info['endpoints_out']:
                for ep in intf_info['endpoints_out']:
                    print(f"    OUT: 0x{ep.bEndpointAddress:02x} "
                          f"({_get_endpoint_type_name(ep.bmAttributes)})")
            if intf_info['endpoints_in']:
                for ep in intf_info['endpoints_in']:
                    print(f"    IN:  0x{ep.bEndpointAddress:02x} "
                          f"({_get_endpoint_type_name(ep.bmAttributes)})")
            if not intf_info['endpoints_out'] and not intf_info['endpoints_in']:
                print(f"    No endpoints found")
        
        print("\nThis device may require control transfers instead of endpoint I/O.")
        print("Use the --scan or --expand-cmds modes which support devices with endpoints,")
        print("or the --get-descriptors mode for control transfer testing.")
        return
    
    try:
        # Log command
        if logger:
            logger.log_command(cmd_bytes)
        
        # Send command
        print("Sending command...")
        dev.write(ep_out, cmd_bytes)
        
        # Wait for response
        time.sleep(0.05)  # Give device time to respond
        
        try:
            # Try to read response with 1 second timeout
            data = dev.read(ep_in, ep_in.wMaxPacketSize, 1000)
            
            if logger:
                logger.log_response(bytes(data))
            
            hex_data = ' '.join([f'{x:02x}' for x in data])
            ascii_data = ''.join([chr(x) if 32 <= x <= 126 else '.' for x in data])
            
            print(f"Response received ({len(data)} bytes):")
            print(f"  HEX:   {hex_data}")
            print(f"  ASCII: {ascii_data}")
            
        except usb.core.USBError as e:
            if "timeout" in str(e).lower():
                print("No response received (timeout)")
            else:
                print(f"Error reading response: {e}")
                
    except usb.core.USBError as e:
        print(f"Error sending command: {e}")
    finally:
        if target_intf:
            try:
                usb.util.release_interface(dev, target_intf.bInterfaceNumber)
            except usb.core.USBError:
                pass

def _get_endpoint_type_name(bmAttributes):
    """Helper function to get endpoint type name from attributes"""
    ep_type = usb.util.endpoint_type(bmAttributes)
    if ep_type == usb.util.ENDPOINT_TYPE_BULK:
        return "BULK"
    elif ep_type == usb.util.ENDPOINT_TYPE_INTR:
        return "INTERRUPT"
    elif ep_type == usb.util.ENDPOINT_TYPE_ISO:
        return "ISOCHRONOUS"
    else:
        return "CONTROL"

def monte_carlo_scan(dev, min_len=1, max_len=8, count=None, skip_patterns=None, prefix=None, postfix=None, logger=None):
    
    print("Starting Monte Carlo Fuzzing...")
    print(f"Length range: {min_len} to {max_len} bytes")
    if count:
        print(f"Iterations: {count}")
    else:
        print("Iterations: Unlimited (Press Ctrl+C to stop)")
    print("WARNING: Sending random data can have unexpected side effects.")

    # Parse prefix/postfix
    prefix_bytes = []
    postfix_bytes = []
    if prefix:
        prefix_hex = prefix.replace(' ', '')
        prefix_bytes = [int(prefix_hex[i:i+2], 16) for i in range(0, len(prefix_hex), 2)]
        print(f"Prefix: {' '.join([f'{x:02x}' for x in prefix_bytes])}")
    if postfix:
        postfix_hex = postfix.replace(' ', '')
        postfix_bytes = [int(postfix_hex[i:i+2], 16) for i in range(0, len(postfix_hex), 2)]
        print(f"Postfix: {' '.join([f'{x:02x}' for x in postfix_bytes])}")

    # Parse skip patterns
    skip_rules = []
    if skip_patterns:
        for pattern in skip_patterns:
            pattern = pattern.strip()
            if pattern.startswith('*') and pattern.endswith('*'):
                # Contains pattern
                hex_val = pattern[1:-1]
                byte_val = int(hex_val, 16)
                skip_rules.append(('contains', byte_val))
                print(f"Skip rule: Any command containing 0x{byte_val:02x}")
            elif pattern.startswith('*'):
                # Ends with pattern
                hex_val = pattern[1:]
                byte_val = int(hex_val, 16)
                skip_rules.append(('ends_with', byte_val))
                print(f"Skip rule: Any command ending with 0x{byte_val:02x}")
            elif pattern.endswith('*'):
                # Starts with pattern
                hex_val = pattern[:-1]
                byte_val = int(hex_val, 16)
                skip_rules.append(('starts_with', byte_val))
                print(f"Skip rule: Any command starting with 0x{byte_val:02x}")
            else:
                # Exact single byte match
                byte_val = int(pattern, 16)
                skip_rules.append(('exact', byte_val))
                print(f"Skip rule: Single-byte command 0x{byte_val:02x}")
    
    def should_skip(cmd_bytes):
        """Check if command should be skipped based on skip rules"""
        for rule_type, byte_val in skip_rules:
            if rule_type == 'exact':
                if len(cmd_bytes) == 1 and cmd_bytes[0] == byte_val:
                    return True
            elif rule_type == 'starts_with':
                if len(cmd_bytes) > 0 and cmd_bytes[0] == byte_val:
                    return True
            elif rule_type == 'ends_with':
                if len(cmd_bytes) > 0 and cmd_bytes[-1] == byte_val:
                    return True
            elif rule_type == 'contains':
                if byte_val in cmd_bytes:
                    return True
        return False

    # Set active config
    try:
        dev.set_configuration()
    except usb.core.USBError:
        pass
    
    cfg = dev.get_active_configuration()
    
    # We need an interface with both IN and OUT endpoints
    target_intf = None
    ep_in = None
    ep_out = None
    
    for intf in cfg:
        # Check for kernel driver
        if dev.is_kernel_driver_active(intf.bInterfaceNumber):
            try:
                dev.detach_kernel_driver(intf.bInterfaceNumber)
            except usb.core.USBError:
                pass
                
        try:
            usb.util.claim_interface(dev, intf.bInterfaceNumber)
        except usb.core.USBError:
            continue
            
        # Look for endpoints - find first IN and first OUT
        temp_in = None
        temp_out = None
        for ep in intf:
            if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN:
                if temp_in is None:  # Take first IN endpoint
                    temp_in = ep
            else:
                if temp_out is None:  # Take first OUT endpoint
                    temp_out = ep
        
        if temp_in and temp_out:
            target_intf = intf
            ep_in = temp_in
            ep_out = temp_out
            print(f"Using Interface {intf.bInterfaceNumber}")
            print(f"  OUT Endpoint: 0x{ep_out.bEndpointAddress:02x}")
            print(f"  IN Endpoint:  0x{ep_in.bEndpointAddress:02x}")
            break
        else:
            try:
                usb.util.release_interface(dev, intf.bInterfaceNumber)
            except usb.core.USBError:
                pass
            
    if not target_intf:
        print("No suitable interface found (need both IN and OUT endpoints).")
        return

    try:
        iteration = 0
        while True:
            if count and iteration >= count:
                break
            
            iteration += 1
            
            # Generate random command
            curr_len = random.randint(min_len, max_len)
            cmd_bytes = [random.randint(0, 255) for _ in range(curr_len)]
            
            if should_skip(cmd_bytes):
                continue
                
            cmd = bytes(prefix_bytes + cmd_bytes + postfix_bytes)
            hex_cmd = ' '.join([f'{x:02x}' for x in cmd])
            
            # Print progress
            print(f"Iter {iteration}: Testing [{hex_cmd}]" + " " * 20, end='\r')
            sys.stdout.flush()

            try:
                if logger:
                    logger.log_command(cmd)
                dev.write(ep_out, cmd)
                time.sleep(0.01)
                try:
                    data = dev.read(ep_in, ep_in.wMaxPacketSize, 50)
                    if logger:
                        logger.log_response(bytes(data))
                    
                    hex_data = ' '.join([f'{x:02x}' for x in data])
                    ascii_data = ''.join([chr(x) if 32 <= x <= 126 else '.' for x in data])
                    
                    # Heuristic Analysis
                    resp_type = "BINARY"
                    if len(data) == 0:
                        resp_type = "EMPTY"
                    elif all(x == 0x00 for x in data):
                        resp_type = "ALL_ZEROS"
                    elif all(x == 0xFF for x in data):
                        resp_type = "ALL_FFs"
                    elif all(32 <= x <= 126 for x in data):
                        resp_type = "ASCII_TEXT"
                    
                    print(f"\n[MATCH] Command {hex_cmd}")
                    print(f"        Type:     {resp_type}")
                    print(f"        Response: {hex_data}")
                    print(f"        ASCII:    {ascii_data}")

                except usb.core.USBError:
                    pass
            except usb.core.USBError as e:
                print(f"\nWrite error on {hex_cmd}: {e}")

    except KeyboardInterrupt:
        print("\nScan stopped by user.")
        if target_intf:
            try:
                usb.util.release_interface(dev, target_intf.bInterfaceNumber)
            except:
                pass
        raise  # Re-raise to propagate to caller
    finally:
        if target_intf:
            try:
                usb.util.release_interface(dev, target_intf.bInterfaceNumber)
            except:
                pass  # Already released in except block

def expand_commands(dev, input_file, iterations_per_byte, skip_patterns=None, postfix=None, logger=None, suffix_mode=False, scan_mode='monte-carlo', bruteforce_max=None, monte_carlo_range=None):
    print(f"Expanding commands from: {input_file}")
    if scan_mode == 'bruteforce':
        print(f"Scan mode: BRUTEFORCE (max length: {bruteforce_max})")
    else:
        print(f"Scan mode: MONTE-CARLO")
        if monte_carlo_range:
            print(f"Length range: {monte_carlo_range[0]}-{monte_carlo_range[1]} bytes")
        print(f"Iterations per byte: {iterations_per_byte}")
    if suffix_mode:
        print(f"Mode: SUFFIX (append bytes at the end)")
    else:
        print(f"Mode: PREFIX (prepend progressively)")
    print("WARNING: Sending random data can have unexpected side effects.")
    
    # Read commands from file
    commands = []
    try:
        with open(input_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Remove CMD: prefix if present
                if line.startswith('CMD:'):
                    line = line[4:].strip()
                # Parse hex string
                hex_str = line.replace(' ', '')
                cmd_bytes = [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]
                if cmd_bytes:
                    commands.append(cmd_bytes)
    except IOError as e:
        print(f"Error reading file: {e}")
        return
    
    if not commands:
        print("No valid commands found in file.")
        return
    
    print(f"Loaded {len(commands)} commands from file.")
    
    # Parse postfix
    postfix_bytes = []
    if postfix:
        postfix_hex = postfix.replace(' ', '')
        postfix_bytes = [int(postfix_hex[i:i+2], 16) for i in range(0, len(postfix_hex), 2)]
        print(f"Postfix: {' '.join([f'{x:02x}' for x in postfix_bytes])}")
    
    # For each command, expand with prefixes or suffixes
    total_tests = 0
    try:
        for base_cmd in commands:
            print(f"\nExpanding command: {' '.join([f'{x:02x}' for x in base_cmd])}")
            
            if suffix_mode:
                # Suffix mode: keep full command as-is, append random/exhaustive bytes
                base_str = ' '.join([f'{x:02x}' for x in base_cmd])
                
                if scan_mode == 'bruteforce':
                    print(f"  Testing with base: {base_str} + bruteforce suffix (up to {bruteforce_max} bytes)")
                    # Run bruteforce_scan with full command as prefix
                    bruteforce_scan(
                        dev,
                        max_length=bruteforce_max,
                        skip_patterns=skip_patterns,
                        prefix=' '.join([f'{x:02x}' for x in base_cmd]),
                        postfix=postfix,
                        logger=logger
                    )
                    # Calculate total tests for bruteforce
                    for length in range(1, bruteforce_max + 1):
                        total_tests += 256 ** length
                else:
                    # Monte carlo mode
                    if monte_carlo_range:
                        min_suffix, max_suffix = monte_carlo_range
                    else:
                        # Default range if not specified
                        min_suffix, max_suffix = 1, 4
                    
                    print(f"  Testing with base: {base_str} + random suffix ({min_suffix}-{max_suffix} bytes, {iterations_per_byte} iterations)")
                    # Run monte_carlo_scan with full command as prefix
                    monte_carlo_scan(
                        dev, 
                        min_len=min_suffix, 
                        max_len=max_suffix, 
                        count=iterations_per_byte,
                        skip_patterns=skip_patterns,
                        prefix=' '.join([f'{x:02x}' for x in base_cmd]),
                        postfix=postfix,
                        logger=logger
                    )
                    total_tests += iterations_per_byte
            else:
                # Prefix mode: progressively prepend prefixes from the command
                for prefix_len in range(1, len(base_cmd) + 1):
                    prefix_bytes = base_cmd[:prefix_len]
                    prefix_str = ' '.join([f'{x:02x}' for x in prefix_bytes])
                    
                    if scan_mode == 'bruteforce':
                        print(f"  Testing with prefix: {prefix_str} + bruteforce (up to {bruteforce_max} bytes)")
                        bruteforce_scan(
                            dev,
                            max_length=bruteforce_max,
                            skip_patterns=skip_patterns,
                            prefix=' '.join([f'{x:02x}' for x in prefix_bytes]),
                            postfix=postfix,
                            logger=logger
                        )
                        # Calculate total tests for bruteforce
                        for length in range(1, bruteforce_max + 1):
                            total_tests += 256 ** length
                    else:
                        # Monte carlo mode
                        if monte_carlo_range:
                            min_len, max_len = monte_carlo_range
                        else:
                            # Default range if not specified
                            min_len, max_len = 1, 4
                        
                        print(f"  Testing with prefix: {prefix_str} ({iterations_per_byte} iterations, {min_len}-{max_len} bytes)")
                        # Run monte_carlo_scan with this prefix
                        monte_carlo_scan(
                            dev,
                            min_len=min_len,
                            max_len=max_len,
                            count=iterations_per_byte,
                            skip_patterns=skip_patterns,
                            prefix=' '.join([f'{x:02x}' for x in prefix_bytes]),
                            postfix=postfix,
                            logger=logger
                        )
                        total_tests += iterations_per_byte
        
        print(f"\nCommand expansion completed. Total tests: {total_tests}")
    except KeyboardInterrupt:
        print(f"\nCommand expansion stopped by user. Total tests run: {total_tests}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="USB Device Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
OPERATION MODES:
  The tool has six main operation modes that cannot be combined:

  1. ENUMERATE MODE (--enumerate)
     List all available USB devices with their VID/PID and details.
     Example: python explore_usb_device.py --enumerate

  2. GET DESCRIPTORS MODE (--get-descriptors <device_id> [max_index])
     Enumerate USB descriptors by trying different descriptor types and indexes.
     Device can be selected by index or use --vid/--pid.
     
     Options:
       --bruteforce-descriptors     Try all descriptor types 0x00-0xFF (default: standard only)
     
     Examples:
       python explore_usb_device.py --get-descriptors 2
       python explore_usb_device.py --get-descriptors 2 50
       python explore_usb_device.py --get-descriptors 2 --bruteforce-descriptors
       python explore_usb_device.py --get-descriptors 0 --vid 0x1234 --pid 0x5678

  3. SEND COMMAND MODE (--send-command <hex_command> or --send-command <device_id> <hex_command>)
     Send a single hex command to a device and display the response.
     Hex command can be space-separated or continuous.
     Device can be selected by index OR by using --vid/--pid (no device_id needed).
     
     Examples:
       python explore_usb_device.py --send-command 2 "AA BB CC DD"
       python explore_usb_device.py --send-command "AABBCCDD" --vid 0x1234 --pid 0x5678
       python explore_usb_device.py --send-command "01 02 03" --vid 0x1234 --pid 0x5678

  4. SEND FILE MODE (--send-file <file> or --send-file <device_id> <file>)
     Send multiple hex commands from a file (one command per line).
     Each line should contain a hex command in the same format as --send-command.
     Device can be selected by index OR by using --vid/--pid (no device_id needed).
     
     Examples:
       python explore_usb_device.py --send-file 2 commands.txt
       python explore_usb_device.py --send-file commands.txt --vid 0x1234 --pid 0x5678
       python explore_usb_device.py --send-file commands.txt --log --vid 0x1234 --pid 0x5678

  5. SCAN MODE (--scan <device_id>)
     Perform direct fuzzing on a selected device.
     Requires one of: --bruteforce or --monte-carlo
     
     Examples:
       python explore_usb_device.py --scan 2 --bruteforce 2 --log
       python explore_usb_device.py --scan 2 --monte-carlo 10000 1 4 --prefix "AA BB"

  6. EXPAND MODE (--expand-cmds <device_id> <file> <iterations>)
     Read known commands from file and expand them with fuzzing.
     Default: Progressive prefix mode with Monte Carlo (1-4 bytes)
     
     Scan Method (choose one):
       --monte-carlo-expand <min> <max> Random fuzzing with custom range
       --bruteforce-expand <max_length> Exhaustive scan up to max length
     
     Mode Modifier:
       --suffix-mode                    Append bytes instead of prefix mode
                                        (keeps full command intact)
     
     Other Options:
       --postfix <hex>                  Additional bytes after all commands
       --skip <pattern>                 Skip certain byte patterns
       --log [folder]                   Enable comprehensive logging
     
     Examples:
       # Default: prefix mode, monte-carlo 1-4 bytes
       python explore_usb_device.py --expand-cmds 2 cmds.txt 1000
       
       # Suffix mode with monte-carlo 1-8 bytes
       python explore_usb_device.py --expand-cmds 2 cmds.txt 1000 --suffix-mode --monte-carlo-expand 1 8
       
       # Suffix mode with bruteforce up to 2 bytes
       python explore_usb_device.py --expand-cmds 2 cmds.txt 1000 --suffix-mode --bruteforce-expand 2
       
       # Prefix mode with bruteforce
       python explore_usb_device.py --expand-cmds 2 cmds.txt 1000 --bruteforce-expand 3

DEVICE SELECTION:
  Use device index from --enumerate OR specify --vid and --pid:
    --scan 2              Select device #2 from enumeration
    --vid 0x1234 --pid 0x5678  Select by Vendor/Product ID

SKIP PATTERNS:
  --skip '40'           Skip single-byte command 0x40
  --skip '40*'          Skip commands starting with 0x40
  --skip '*40'          Skip commands ending with 0x40
  --skip '*40*'         Skip commands containing 0x40
  (Can specify multiple --skip flags)

PREFIX/POSTFIX MODE vs SUFFIX MODE:
  PREFIX MODE (default for --expand-cmds):
    Command: AA BB CC
    Tests: AA + random, AA BB + random, AA BB CC + random
  
  SUFFIX MODE (--suffix-mode):
    Command: AA BB CC
    Tests: AA BB CC + random/exhaustive bytes
    (Keeps full command intact, only appends)
"""
    )
    
    # Main operation modes
    parser.add_argument("--enumerate", action="store_true", 
                       help="List all available USB devices")
    parser.add_argument("--get-descriptors", nargs='+', metavar=('DEVICE_ID', 'MAX_INDEX'), type=int,
                       help="Get USB descriptors: DEVICE_ID [MAX_INDEX] (default MAX_INDEX: 255)")
    parser.add_argument("--scan", nargs='?', const=0, type=int, metavar='DEVICE_ID',
                       help="Scan mode: select device by index or use --vid/--pid")
    parser.add_argument("--expand-cmds", nargs=3, metavar=('DEVICE_ID', 'INPUT_FILE', 'ITERATIONS'),
                       help="Expand mode: test variations of known commands from file")
    parser.add_argument("--send-command", nargs='+', metavar='HEX_COMMAND',
                       help="Send a single hex command (e.g., 'AA BB CC' or 'AABBCC'). Use --vid/--pid to select device.")
    parser.add_argument("--send-file", nargs='+', metavar='FILE',
                       help="Send hex commands from file (one command per line). Use --vid/--pid to select device.")
    
    # Device selection
    parser.add_argument("--vid", type=str, metavar='VID',
                       help="Vendor ID in hex (e.g., 0x1234)")
    parser.add_argument("--pid", type=str, metavar='PID',
                       help="Product ID in hex (e.g., 0x5678)")
    
    # Scan mode options
    parser.add_argument("--bruteforce", type=int, metavar='MAX_LENGTH',
                       help="[--scan] Exhaustive scan: test all byte combinations up to MAX_LENGTH")
    parser.add_argument("--bruteforce-descriptors", action="store_true",
                       help="[--get-descriptors] Try all descriptor types 0x00-0xFF (default: standard types only)")
    parser.add_argument("--monte-carlo", nargs=3, metavar=('ITERATIONS', 'MIN_LEN', 'MAX_LEN'), type=int,
                       help="[--scan] Random fuzzing: iterations and length range")
    
    # Expand mode options
    parser.add_argument("--monte-carlo-expand", nargs=2, metavar=('MIN_LEN', 'MAX_LEN'), type=int,
                       help="[--expand-cmds] Use Monte Carlo with custom length range (default: 1-4)")
    parser.add_argument("--bruteforce-expand", type=int, metavar='MAX_LENGTH',
                       help="[--expand-cmds] Use bruteforce instead of Monte Carlo")
    parser.add_argument("--suffix-mode", action="store_true",
                       help="[--expand-cmds] Keep command intact and append bytes (vs. progressive prefix)")
    
    # Common options
    parser.add_argument("--prefix", type=str, metavar='HEX',
                       help="Prepend bytes to all commands (e.g., 'AA BB' or 'AABB')")
    parser.add_argument("--postfix", type=str, metavar='HEX',
                       help="Append bytes to all commands (e.g., 'CC DD' or 'CCDD')")
    parser.add_argument("--skip", type=str, action='append', metavar='PATTERN',
                       help="Skip byte patterns: '40' (exact), '40*' (starts), '*40' (ends), '*40*' (contains)")
    parser.add_argument("--log", nargs='?', const='', metavar='FOLDER',
                       help="Enable logging to folder (default: session_<timestamp>)")
    
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
    if args.enumerate:
        list_all_devices()
        sys.exit(0)

    target_vid = None
    target_pid = None
    dev = None

    # Handle --get-descriptors
    if args.get_descriptors is not None:
        # Parse arguments: device_id [max_index]
        device_id = args.get_descriptors[0]
        max_index = args.get_descriptors[1] if len(args.get_descriptors) > 1 else 255
        
        # Select device using common function
        dev, target_vid, target_pid = select_device(device_id, args.vid, args.pid)
        
        # Initialize logger if requested
        logger = None
        if args.log is not None:
            logger = USBLogger(args.log if args.log else None)
        
        # Run descriptor enumeration
        get_descriptors(dev, max_index, bruteforce=args.bruteforce_descriptors, logger=logger)
        sys.exit(0)

    # Handle --send-command
    if args.send_command:
        # Parse arguments - can be either just hex_command or device_id hex_command
        if len(args.send_command) == 1:
            # Just hex command, must use --vid/--pid
            hex_command = args.send_command[0]
            device_id = 0
        else:
            # device_id and hex command
            device_id_str = args.send_command[0]
            hex_command = args.send_command[1]
            try:
                device_id = int(device_id_str)
            except ValueError:
                # First arg is not a number, treat it as hex command
                hex_command = device_id_str
                device_id = 0
        
        # Select device using common function
        dev, target_vid, target_pid = select_device(device_id, args.vid, args.pid)
        
        # Initialize logger if requested
        logger = None
        if args.log is not None:
            logger = USBLogger(args.log if args.log else None)
        
        # Send the command
        send_single_command(dev, hex_command, logger=logger)
        sys.exit(0)
    
    # Handle --send-file
    if args.send_file:
        # Parse arguments - can be either just file_path or device_id file_path
        if len(args.send_file) == 1:
            # Just file path, must use --vid/--pid
            file_path = args.send_file[0]
            device_id = 0
        else:
            # device_id and file path
            device_id_str = args.send_file[0]
            file_path = args.send_file[1]
            try:
                device_id = int(device_id_str)
            except ValueError:
                # First arg is not a number, treat it as file path
                file_path = device_id_str
                device_id = 0
        
        # Select device using common function
        dev, target_vid, target_pid = select_device(device_id, args.vid, args.pid)
        
        # Initialize logger if requested
        logger = None
        if args.log is not None:
            logger = USBLogger(args.log if args.log else None)
        
        # Read commands from file
        try:
            with open(file_path, 'r') as f:
                commands = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            
            if not commands:
                print(f"No commands found in {file_path}")
                sys.exit(1)
            
            print(f"Loaded {len(commands)} command(s) from {file_path}")
            print("=" * 80)
            
            for idx, cmd_hex in enumerate(commands, 1):
                print(f"\n{'=' * 80}")
                print(f"Command {idx}/{len(commands)}")
                print("=" * 80)
                send_single_command(dev, cmd_hex, logger=logger)
                
                # Small delay between commands
                if idx < len(commands):
                    time.sleep(0.1)
            
            print(f"\n{'=' * 80}")
            print(f"Completed: {len(commands)} command(s) sent")
            print("=" * 80)
            
        except FileNotFoundError:
            print(f"Error: File not found - {file_path}")
            sys.exit(1)
        except IOError as e:
            print(f"Error reading file: {e}")
            sys.exit(1)
        
        sys.exit(0)

    # Handle --expand-cmds first (independent from --scan)

    # Handle --expand-cmds first (independent from --scan)
    if args.expand_cmds:
        device_id_str, input_file, iterations_str = args.expand_cmds
        device_id = int(device_id_str)
        iterations_per_byte = int(iterations_str)
        
        # Select device using common function
        dev, target_vid, target_pid = select_device(device_id, args.vid, args.pid)
        
        # Initialize logger if requested
        logger = None
        if args.log is not None:
            logger = USBLogger(args.log if args.log else None)
        
        # Determine scan mode
        if args.bruteforce_expand:
            expand_commands(dev, input_file, iterations_per_byte, skip_patterns=args.skip, postfix=args.postfix, logger=logger, suffix_mode=args.suffix_mode, scan_mode='bruteforce', bruteforce_max=args.bruteforce_expand)
        else:
            expand_commands(dev, input_file, iterations_per_byte, skip_patterns=args.skip, postfix=args.postfix, logger=logger, suffix_mode=args.suffix_mode, scan_mode='monte-carlo', monte_carlo_range=args.monte_carlo_expand)
        sys.exit(0)

    # Handle --scan mode
    if args.scan is not None:
        # Select device using common function
        dev, target_vid, target_pid = select_device(args.scan, args.vid, args.pid)

        # Initialize logger if requested
        logger = None
        if args.log is not None:
            logger = USBLogger(args.log if args.log else None)
        
        if args.bruteforce:
            bruteforce_scan(dev, max_length=args.bruteforce, skip_patterns=args.skip, prefix=args.prefix, postfix=args.postfix, logger=logger)
        elif args.monte_carlo:
            count, min_len, max_len = args.monte_carlo
            monte_carlo_scan(dev, min_len=min_len, max_len=max_len, count=count, skip_patterns=args.skip, prefix=args.prefix, postfix=args.postfix, logger=logger)
        else:
            print("Error: --scan requires either --bruteforce or --monte-carlo option")
            sys.exit(1)
    elif dev is not None:
        # Default action: enumerate endpoints for the specific device
        enumerate_endpoints(dev, target_vid, target_pid)
    else:
        # No mode specified and no device selected
        parser.print_help(sys.stderr)
        sys.exit(1)
