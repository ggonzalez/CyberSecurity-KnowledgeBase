#!/usr/bin/env python3
"""
GaBL-E: BLE Fuzzer for macOS
A Bluetooth Low Energy fuzzer for security testing
"""

import asyncio
import argparse
import sys
import random
import time
from bleak import BleakScanner, BleakClient
from typing import Optional, List, Dict, Tuple


class BLEFuzzer:
    """Main BLE Fuzzer class"""
    
    def __init__(self):
        self.devices = []
        self.selected_device = None
        self.client = None
    
    @staticmethod
    def _format_hex_with_ascii(data: bytes, bytes_per_line: int = 16) -> str:
        """
        Format bytes as hex with ASCII representation (hexdump style)
        
        Args:
            data: Bytes to format
            bytes_per_line: Number of bytes per line
            
        Returns:
            Formatted string with hex and ASCII
        """
        if not data:
            return ""
        
        lines = []
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i + bytes_per_line]
            
            # Hex representation
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            
            # ASCII representation
            ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            
            # Combine
            lines.append(f"{hex_str:<{bytes_per_line * 3}} |{ascii_str}|")
        
        return '\n    '.join(lines)
    
    @staticmethod
    def _identify_service_type(uuid: str) -> str:
        """
        Identify the type of BLE service based on UUID
        
        Args:
            uuid: Service UUID
            
        Returns:
            Service type description
        """
        # Standard GATT services (16-bit UUIDs)
        known_services = {
            '00001800-0000-1000-8000-00805f9b34fb': 'Generic Access',
            '00001801-0000-1000-8000-00805f9b34fb': 'Generic Attribute',
            '0000180a-0000-1000-8000-00805f9b34fb': 'Device Information',
            '0000180f-0000-1000-8000-00805f9b34fb': 'Battery Service',
            '00001805-0000-1000-8000-00805f9b34fb': 'Current Time Service',
            '00001811-0000-1000-8000-00805f9b34fb': 'Alert Notification Service',
            '0000180d-0000-1000-8000-00805f9b34fb': 'Heart Rate',
            '00001812-0000-1000-8000-00805f9b34fb': 'Human Interface Device',
            '00001816-0000-1000-8000-00805f9b34fb': 'Cycling Speed and Cadence',
            '00001818-0000-1000-8000-00805f9b34fb': 'Cycling Power',
            '0000181a-0000-1000-8000-00805f9b34fb': 'Environmental Sensing',
            '0000181c-0000-1000-8000-00805f9b34fb': 'User Data',
            '0000181d-0000-1000-8000-00805f9b34fb': 'Weight Scale',
        }
        
        uuid_lower = uuid.lower()
        return known_services.get(uuid_lower, 'Custom Service')
    
    async def scan_devices(self, verbose: bool = False, duration: int = 5):
        """
        Scan for BLE devices in range
        
        Args:
            verbose: If True, display all available information
            duration: Scan duration in seconds
        """
        print(f"[*] Scanning for BLE devices for {duration} seconds...")
        print("-" * 80)
        
        # Always get advertisement data to access RSSI and other info
        devices = await BleakScanner.discover(timeout=duration, return_adv=True)
        
        # Handle different return types from Bleak
        if isinstance(devices, dict):
            # Dictionary format: {device: adv_data} or {address: (device, adv_data)}
            device_list = []
            for key, value in devices.items():
                if hasattr(key, 'address'):  # key is a BLEDevice
                    device_list.append((key, value))
                elif isinstance(value, tuple) and len(value) == 2:  # value is (device, adv_data)
                    device_list.append(value)
                else:
                    # Try to construct from available data
                    device_list.append((key, value))
            devices = dict(device_list)
            self.devices = list(devices.keys())
        else:
            # List format (older versions)
            self.devices = devices
        
        if not devices:
            print("[!] No devices found")
            return
        
        print(f"[+] Found {len(devices)} device(s)\n")
        
        if verbose:
            self._display_verbose(devices)
        else:
            self._display_short(devices)
    
    def _display_short(self, devices_dict):
        """Display devices in short format with key information"""
        print(f"{'#':<3} {'Device Name':<35} {'UUID':<38} {'RSSI':<8}")
        print("-" * 90)
        
        # devices_dict is a dictionary of {BLEDevice: AdvertisementData}
        idx = 1
        for device, adv_data in devices_dict.items():
            try:
                # Handle if device is a BLEDevice object
                if hasattr(device, 'name') and hasattr(device, 'address'):
                    name = device.name if device.name else "<Unknown>"
                    uuid = device.address
                # Handle if device is a string (UUID) and we need to extract from adv_data
                elif isinstance(device, str):
                    uuid = device
                    name = adv_data.local_name if hasattr(adv_data, 'local_name') and adv_data.local_name else "<Unknown>"
                else:
                    # Fallback
                    name = "<Unknown>"
                    uuid = str(device)
                
                rssi = f"{adv_data.rssi}" if hasattr(adv_data, 'rssi') and adv_data.rssi is not None else "N/A"
                print(f"{idx:<3} {name:<35} {uuid:<38} {rssi:<8}")
                idx += 1
            except Exception as e:
                print(f"Error displaying device {idx}: {e}")
                idx += 1
    
    def _display_verbose(self, devices_dict):
        """Display all available information about devices"""
        # devices_dict is a dictionary of {BLEDevice: AdvertisementData}
        idx = 1
        for device, adv_data in devices_dict.items():
            print(f"\n{'='*80}")
            print(f"[Device {idx}]")
            print(f"{'='*80}")
            
            try:
                # Handle if device is a BLEDevice object
                if hasattr(device, 'name') and hasattr(device, 'address'):
                    name = device.name if device.name else '<Unknown>'
                    uuid = device.address
                # Handle if device is a string (UUID)
                elif isinstance(device, str):
                    uuid = device
                    name = adv_data.local_name if hasattr(adv_data, 'local_name') and adv_data.local_name else '<Unknown>'
                else:
                    name = '<Unknown>'
                    uuid = str(device)
                
                print(f"  Name:              {name}")
                print(f"  Address (UUID):    {uuid}")
                
                # RSSI
                if hasattr(adv_data, 'rssi') and adv_data.rssi is not None:
                    print(f"  RSSI:              {adv_data.rssi} dBm")
                else:
                    print(f"  RSSI:              N/A")
                
                # Advertisement data details
                if adv_data:
                    # Service UUIDs
                    if hasattr(adv_data, 'service_uuids') and adv_data.service_uuids:
                        print(f"\n  [Service UUIDs]")
                        for service_uuid in adv_data.service_uuids:
                            print(f"    - {service_uuid}")
                    
                    # Manufacturer data
                    if hasattr(adv_data, 'manufacturer_data') and adv_data.manufacturer_data:
                        print(f"\n  [Manufacturer Data]")
                        for company_id, data in adv_data.manufacturer_data.items():
                            print(f"    Company ID: {company_id} (0x{company_id:04x})")
                            print(f"    Data:")
                            print(f"    {self._format_hex_with_ascii(data)}")
                    
                    # Service data
                    if hasattr(adv_data, 'service_data') and adv_data.service_data:
                        print(f"\n  [Service Data]")
                        for service_uuid, data in adv_data.service_data.items():
                            print(f"    Service: {service_uuid}")
                            print(f"    Data:")
                            print(f"    {self._format_hex_with_ascii(data)}")
                    
                    # TX Power
                    if hasattr(adv_data, 'tx_power') and adv_data.tx_power is not None:
                        print(f"\n  [TX Power Level]")
                        print(f"    {adv_data.tx_power} dBm")
                    
                    # Local Name
                    if hasattr(adv_data, 'local_name') and adv_data.local_name:
                        print(f"\n  [Local Name]")
                        print(f"    {adv_data.local_name}")
                    
                    # Platform data (macOS specific)
                    if hasattr(adv_data, 'platform_data') and adv_data.platform_data:
                        print(f"\n  [Platform Data]")
                        print(f"    {adv_data.platform_data}")
                
            except Exception as e:
                print(f"  Error displaying device details: {e}")
            
            print(f"\n{'-'*80}")
            idx += 1
    
    async def connect_device(self, address: str):
        """
        Connect to a BLE device by UUID
        
        Args:
            address: UUID of the device to connect to
        """
        print(f"[*] Attempting to connect to {address}...")
        
        try:
            self.client = BleakClient(address)
            await self.client.connect()
            
            if self.client.is_connected:
                print(f"[+] Successfully connected to {address}")
                self.selected_device = address
                return True
            else:
                print(f"[!] Failed to connect to {address}")
                return False
        except Exception as e:
            print(f"[!] Error connecting to device: {e}")
            return False
    
    async def enumerate_characteristics(self):
        """
        Enumerate and display all services and characteristics
        """
        if not self.client or not self.client.is_connected:
            print("[!] Not connected to any device")
            return
        
        print("\n[*] Enumerating services and characteristics...")
        print("=" * 80)
        
        read_write_chars = []
        readable_chars = []
        writeable_chars = []
        services_by_type = {}
        
        try:
            services = self.client.services
            
            for service in services:
                service_type = self._identify_service_type(service.uuid)
                print(f"\n[Service] {service.uuid}")
                print(f"  Type: {service_type}")
                print(f"  Description: {service.description}")
                print(f"  Handle: 0x{service.handle:04x}")
                
                # Initialize service type in dictionary if not present
                if service_type not in services_by_type:
                    services_by_type[service_type] = []
                
                service_chars = []
                
                for char in service.characteristics:
                    print(f"\n  [Characteristic] {char.uuid}")
                    print(f"    Description: {char.description}")
                    print(f"    Handle: 0x{char.handle:04x}")
                    
                    # Check for read/write capabilities
                    properties = char.properties
                    can_read = 'read' in properties
                    can_write = 'write' in properties or 'write-without-response' in properties
                    can_notify = 'notify' in properties
                    can_indicate = 'indicate' in properties
                    
                    # Track readable and writeable characteristics
                    if can_read and can_write:
                        read_write_chars.append((service_type, char.uuid, char.description))
                    elif can_read:
                        readable_chars.append((service_type, char.uuid, char.description))
                    elif can_write:
                        writeable_chars.append((service_type, char.uuid, char.description))
                    
                    # Display capabilities clearly
                    capabilities = []
                    if can_read:
                        capabilities.append("READ")
                    if can_write:
                        if 'write' in properties:
                            capabilities.append("WRITE")
                        if 'write-without-response' in properties:
                            capabilities.append("WRITE_NO_RESP")
                    if can_notify:
                        capabilities.append("NOTIFY")
                    if can_indicate:
                        capabilities.append("INDICATE")
                    
                    print(f"    Capabilities: {' | '.join(capabilities) if capabilities else 'None'}")
                    print(f"    Properties: {', '.join(properties)}")
                    
                    # Store characteristic info
                    service_chars.append({
                        'uuid': char.uuid,
                        'description': char.description,
                        'capabilities': capabilities
                    })
                    
                    # Display descriptors if any
                    if char.descriptors:
                        print(f"    Descriptors:")
                        for desc in char.descriptors:
                            print(f"      - {desc.uuid} (Handle: 0x{desc.handle:04x})")
                
                services_by_type[service_type].extend(service_chars)
                print("-" * 80)
            
            # Print summary grouped by service type
            print("\n" + "=" * 80)
            print("[Summary by Service Type]")
            print("=" * 80)
            
            for service_type, chars in services_by_type.items():
                if chars:
                    print(f"\n[{service_type}] ({len(chars)} characteristics)")
                    for char_info in chars:
                        cap_str = ' | '.join(char_info['capabilities']) if char_info['capabilities'] else 'None'
                        print(f"  [{cap_str}] {char_info['uuid']}")
                        if char_info['description'] and char_info['description'] != 'Unknown':
                            print(f"      ({char_info['description']})")
            
            print("\n" + "=" * 80)
            print("[Quick Reference]")
            print("=" * 80)
            
            if read_write_chars:
                print(f"\n[Read/Write Characteristics] ({len(read_write_chars)})")
                for service_type, uuid, description in read_write_chars:
                    desc_str = f" - {description}" if description and description != 'Unknown' else ""
                    print(f"  - {uuid} [{service_type}]{desc_str}")
            else:
                print("\n[Read/Write Characteristics] None")
            
            if readable_chars:
                print(f"\n[Read-Only Characteristics] ({len(readable_chars)})")
                for service_type, uuid, description in readable_chars:
                    desc_str = f" - {description}" if description and description != 'Unknown' else ""
                    print(f"  - {uuid} [{service_type}]{desc_str}")
            else:
                print("\n[Read-Only Characteristics] None")
            
            if writeable_chars:
                print(f"\n[Write-Only Characteristics] ({len(writeable_chars)})")
                for service_type, uuid, description in writeable_chars:
                    desc_str = f" - {description}" if description and description != 'Unknown' else ""
                    print(f"  - {uuid} [{service_type}]{desc_str}")
            else:
                print("\n[Write-Only Characteristics] None")
            
            print("\n" + "=" * 80)
        
        except Exception as e:
            print(f"[!] Error enumerating characteristics: {e}")
    
    async def read_characteristic(self, uuid: str):
        """
        Read a specific characteristic
        
        Args:
            uuid: UUID of the characteristic to read, or "*" to read all readable characteristics
        """
        if not self.client or not self.client.is_connected:
            print("[!] Not connected to any device")
            return
        
        # Handle wildcard to read all characteristics
        if uuid == "*":
            await self.read_all_characteristics()
            return
        
        try:
            print(f"[*] Reading characteristic {uuid}...")
            value = await self.client.read_gatt_char(uuid)
            
            print(f"[+] Read {len(value)} bytes:")
            print(f"    {self._format_hex_with_ascii(value)}")
            
            # Try to decode as string
            try:
                decoded = value.decode('utf-8')
                print(f"[+] UTF-8 String: {decoded}")
            except:
                pass
            
            return value
        
        except Exception as e:
            print(f"[!] Error reading characteristic: {e}")
            return None
    
    async def read_all_characteristics(self):
        """
        Read all readable characteristics from the connected device
        """
        if not self.client or not self.client.is_connected:
            print("[!] Not connected to any device")
            return
        
        print("\n[*] Reading all characteristics...")
        print("=" * 80)
        
        try:
            services = self.client.services
            total_read = 0
            total_failed = 0
            
            for service in services:
                service_type = self._identify_service_type(service.uuid)
                service_has_readable = False
                
                for char in service.characteristics:
                    properties = char.properties
                    can_read = 'read' in properties
                    
                    if can_read:
                        if not service_has_readable:
                            print(f"\n[Service: {service_type}]")
                            print(f"  UUID: {service.uuid}")
                            service_has_readable = True
                        
                        print(f"\n  [Reading] {char.uuid}")
                        if char.description and char.description != 'Unknown':
                            print(f"    Description: {char.description}")
                        
                        try:
                            value = await self.client.read_gatt_char(char.uuid)
                            print(f"    Success! Read {len(value)} bytes:")
                            print(f"    {self._format_hex_with_ascii(value)}")
                            
                            # Try to decode as string
                            try:
                                decoded = value.decode('utf-8')
                                if decoded.isprintable():
                                    print(f"    UTF-8: {decoded}")
                            except:
                                pass
                            
                            total_read += 1
                        except Exception as e:
                            print(f"    Failed: {e}")
                            total_failed += 1
            
            # Summary
            print("\n" + "=" * 80)
            print(f"[Summary] Successfully read {total_read} characteristic(s)")
            if total_failed > 0:
                print(f"          Failed to read {total_failed} characteristic(s)")
            print("=" * 80)
        
        except Exception as e:
            print(f"[!] Error reading characteristics: {e}")
    
    async def write_characteristic(self, uuid: str, data: bytes, response: bool = True):
        """
        Write to a specific characteristic
        
        Args:
            uuid: UUID of the characteristic to write to
            data: Data to write (as bytes)
            response: Whether to wait for a response
        """
        if not self.client or not self.client.is_connected:
            print("[!] Not connected to any device")
            return
        
        try:
            print(f"[*] Writing to characteristic {uuid}...")
            print(f"[*] Data ({len(data)} bytes):")
            print(f"    {self._format_hex_with_ascii(data)}")
            
            await self.client.write_gatt_char(uuid, data, response=response)
            print(f"[+] Successfully wrote {len(data)} bytes")
            
            return True
        
        except Exception as e:
            print(f"[!] Error writing to characteristic: {e}")
            return False
    
    async def disconnect(self):
        """Disconnect from the current device"""
        if self.client and self.client.is_connected:
            await self.client.disconnect()
            print(f"[+] Disconnected from {self.selected_device}")
            self.selected_device = None
    
    def _generate_cmd_injection(self) -> bytes:
        """Generate command injection payloads"""
        commands = [
            'reboot', 'halt', 'shutdown', 'poweroff', 'init 0',
            'rm -rf /', 'dd if=/dev/zero of=/dev/sda',
            'cat /etc/passwd', 'cat /etc/shadow', 'id', 'whoami',
            'uname -a', 'ps aux', 'netstat -an'
        ]
        
        wrappers = [
            lambda c: c,  # plain
            lambda c: f'`{c}`',  # backticks
            lambda c: f'$({c})',  # command substitution
            lambda c: f'{{$({c})}}',  # variable substitution
            lambda c: f';{c};',  # semicolon separator
            lambda c: f'|{c}',  # pipe
            lambda c: f'||{c}',  # logical OR
            lambda c: f'&&{c}',  # logical AND
            lambda c: f'\n{c}\n',  # newline
            lambda c: f'%0a{c}%0a',  # URL encoded newline
            lambda c: f'${{IFS}}{c}',  # IFS injection
            lambda c: f'$(({c}))',  # arithmetic expansion
            lambda c: f'`{c}`||`{c}`',  # multiple attempts
        ]
        
        cmd = random.choice(commands)
        wrapper = random.choice(wrappers)
        payload = wrapper(cmd)
        return payload.encode('utf-8')
    
    def _generate_format_string(self) -> bytes:
        """Generate format string attack payloads"""
        patterns = [
            '%s' * random.randint(1, 20),
            '%x' * random.randint(1, 20),
            '%n' * random.randint(1, 10),
            '%p' * random.randint(1, 15),
            '%s%s%s%n%n%n',
            '%x%x%x%n%n%n',
            '%08x.' * random.randint(1, 20),
            '%s' + '%x' * 10 + '%n',
            '%p%p%p%p%s%n',
            '%.10000x',  # large width
            '%*10000d',  # dynamic width
            '%$' + str(random.randint(1, 100)) + '$x',  # positional
            '%1$s%2$s%3$s%4$n',
            'AAAA' + '%x' * 10 + '%n',
            '\x41' * 4 + '%x' * 10 + '%s',
        ]
        
        payload = random.choice(patterns)
        return payload.encode('utf-8')
    
    def _generate_length_attack(self) -> bytes:
        """Generate length-based attack payloads"""
        length_types = [
            lambda: b'A' * 255,  # max BLE packet
            lambda: b'A' * 256,  # just over max
            lambda: b'A' * 512,  # double max
            lambda: b'A' * 1024,  # 1KB
            lambda: b'A' * 4096,  # 4KB
            lambda: b'A' * 8192,  # 8KB
            lambda: b'A' * (2**15 - 1),  # signed int16 max
            lambda: b'A' * (2**16 - 1),  # unsigned int16 max
            lambda: b'A' * random.randint(256, 1000),  # random large
            lambda: b'A' * (2**i for i in range(8, 13)).__next__(),  # power of 2
            lambda: b'\x00' * 1024,  # null bytes
            lambda: bytes([0xFF]) * 1024,  # max bytes
        ]
        
        generator = random.choice(length_types)
        return generator()
    
    def _generate_tlv_attack(self) -> bytes:
        """Generate malformed TLV (Type-Length-Value) structures"""
        tlv_patterns = [
            # Malformed length - length > actual value
            lambda: bytes([0x01, 0xFF, 0x41, 0x42]),  # Type=1, Len=255, Value=2 bytes
            
            # Zero length
            lambda: bytes([0x01, 0x00]),
            
            # Negative length (using signed interpretation)
            lambda: bytes([0x01, 0xFF]),
            
            # Multiple nested TLVs
            lambda: self._create_nested_tlv(random.randint(1, 5)),
            
            # Sequential TLVs with length mismatches
            lambda: bytes([0x01, 0x10] + [0x41] * 5 + [0x02, 0x20] + [0x42] * 3),
            
            # TLV with huge claimed length
            lambda: bytes([0x01, 0xFF, 0xFF] + [0x41] * 10),
            
            # Overlapping TLVs
            lambda: bytes([0x01, 0x05, 0x41, 0x02, 0x03, 0x42, 0x43]),
            
            # TLV length exceeds packet
            lambda: bytes([0x01, 0xFE] + [0x41] * 50),
            
            # Multiple TLVs one after another (valid structure)
            lambda: b''.join([bytes([i, random.randint(1, 10)] + [0x41] * random.randint(1, 10)) 
                             for i in range(random.randint(2, 5))]),
        ]
        
        generator = random.choice(tlv_patterns)
        return generator()
    
    def _create_nested_tlv(self, depth: int) -> bytes:
        """Create nested TLV structures"""
        if depth <= 0:
            return bytes([0x41])  # base value
        
        inner = self._create_nested_tlv(depth - 1)
        tlv_type = random.randint(1, 10)
        # Intentionally mismatched length
        claimed_length = len(inner) + random.choice([-2, -1, 1, 2, 10]) if random.random() > 0.5 else len(inner)
        claimed_length = max(0, min(255, claimed_length))
        
        return bytes([tlv_type, claimed_length]) + inner
    
    def _generate_markov_data(self, length: int = None) -> bytes:
        """Generate random data using Markov chain process (stochastic)"""
        if length is None:
            length = random.randint(10, 255)
        
        # Simple Markov chain with transition probabilities
        # States: 0x00, 0xFF, printable ASCII, control chars, random
        states = ['null', 'max', 'ascii', 'control', 'random']
        
        # Transition matrix (simplified)
        transitions = {
            'null': {'null': 0.3, 'max': 0.1, 'ascii': 0.3, 'control': 0.2, 'random': 0.1},
            'max': {'null': 0.1, 'max': 0.3, 'ascii': 0.2, 'control': 0.2, 'random': 0.2},
            'ascii': {'null': 0.1, 'max': 0.1, 'ascii': 0.5, 'control': 0.1, 'random': 0.2},
            'control': {'null': 0.2, 'max': 0.1, 'ascii': 0.2, 'control': 0.3, 'random': 0.2},
            'random': {'null': 0.2, 'max': 0.2, 'ascii': 0.2, 'control': 0.2, 'random': 0.2},
        }
        
        data = []
        current_state = random.choice(states)
        
        for _ in range(length):
            # Generate byte based on current state
            if current_state == 'null':
                byte = 0x00
            elif current_state == 'max':
                byte = 0xFF
            elif current_state == 'ascii':
                byte = random.randint(32, 126)  # printable ASCII
            elif current_state == 'control':
                byte = random.randint(0, 31)  # control characters
            else:  # random
                byte = random.randint(0, 255)
            
            data.append(byte)
            
            # Transition to next state
            probs = transitions[current_state]
            rand = random.random()
            cumulative = 0
            for next_state, prob in probs.items():
                cumulative += prob
                if rand <= cumulative:
                    current_state = next_state
                    break
        
        return bytes(data)
    
    def generate_fuzz_data(self, length: int = None, strategy: str = 'basic') -> bytes:
        """
        Generate fuzz data based on selected strategy
        
        Args:
            length: Specific length for the payload (if None, random or strategy-dependent)
            strategy: Fuzzing strategy to use:
                - 'basic': Basic random patterns (default)
                - 'cmd_injection': Command injection attempts
                - 'format_string': Format string attacks
                - 'length': Length-based attacks
                - 'tlv': Malformed TLV structures
                - 'markov': Markov chain random data
                - 'all': Randomly select from all strategies
        
        Returns:
            Bytes of fuzz data
        """
        if strategy == 'cmd_injection':
            return self._generate_cmd_injection()
        
        elif strategy == 'format_string':
            return self._generate_format_string()
        
        elif strategy == 'length':
            return self._generate_length_attack()
        
        elif strategy == 'tlv':
            return self._generate_tlv_attack()
        
        elif strategy == 'markov':
            return self._generate_markov_data(length)
        
        elif strategy == 'all':
            # Randomly select a strategy
            strategies = ['basic', 'cmd_injection', 'format_string', 'length', 'tlv', 'markov']
            selected = random.choice(strategies)
            return self.generate_fuzz_data(length, selected)
        
        else:  # 'basic' or default
            if length is None:
                length = random.randint(1, 255)
            
            # Various basic fuzzing patterns
            patterns = [
                # Random bytes
                lambda l: bytes([random.randint(0, 255) for _ in range(l)]),
                # All zeros
                lambda l: b'\x00' * l,
                # All ones (0xFF)
                lambda l: b'\xFF' * l,
                # Alternating pattern
                lambda l: bytes([0xAA if i % 2 == 0 else 0x55 for i in range(l)]),
                # Incrementing bytes
                lambda l: bytes([(i % 256) for i in range(l)]),
                # Decrementing bytes
                lambda l: bytes([(255 - i % 256) for i in range(l)]),
                # Random ASCII printable
                lambda l: bytes([random.randint(32, 126) for _ in range(l)]),
                # Boundary values
                lambda l: b'\x00\xFF\x7F\x80' * (l // 4) + b'\x00' * (l % 4),
            ]
            
            # Select a random pattern
            pattern = random.choice(patterns)
            return pattern(length)
    
    async def fuzz_characteristic(self, uuid: str, iterations: int = 10000, response: bool = True, read_after_write: bool = False, verbose: bool = False, strategy: str = 'basic'):
        """
        Fuzz a specific write characteristic
        
        Args:
            uuid: UUID of the characteristic to fuzz
            iterations: Number of fuzzing iterations (default: 10000)
            response: Whether to wait for write response
            read_after_write: If True and characteristic supports read, read after each write
            verbose: If True, print written and read data for each iteration
            strategy: Fuzzing strategy (basic, cmd_injection, format_string, length, tlv, markov, all)
        """
        if not self.client or not self.client.is_connected:
            print("[!] Not connected to any device")
            return
        
        print(f"\n[*] Starting fuzzing on characteristic {uuid}")
        print(f"[*] Iterations: {iterations}")
        print(f"[*] Strategy: {strategy}")
        print(f"[*] Verbose: {verbose}")
        print(f"[*] Press Ctrl+C to stop")
        print("=" * 80)
        
        successful = 0
        failed = 0
        start_time = time.time()
        
        try:
            for i in range(iterations):
                # Generate fuzz data
                fuzz_data = self.generate_fuzz_data(strategy=strategy)
                
                # Write fuzz data
                try:
                    if verbose:
                        print(f"\n[Iteration {i + 1}] Writing {len(fuzz_data)} bytes:")
                        print(f"    {self._format_hex_with_ascii(fuzz_data)}")
                    
                    await self.client.write_gatt_char(uuid, fuzz_data, response=response)
                    successful += 1
                    
                    # Read after write if requested
                    if read_after_write:
                        try:
                            value = await self.client.read_gatt_char(uuid)
                            
                            if verbose:
                                print(f"[Iteration {i + 1}] Read {len(value)} bytes:")
                                print(f"    {self._format_hex_with_ascii(value)}")
                                if value != fuzz_data:
                                    print(f"    [!] Value differs from written data")
                            elif value != fuzz_data:
                                # Only print mismatches in non-verbose mode
                                print(f"[!] Iteration {i + 1}: Read value differs from written value")
                        except Exception as e:
                            if verbose:
                                print(f"[Iteration {i + 1}] Read failed: {e}")
                    
                    # Print progress every 100 iterations (only in non-verbose mode)
                    if not verbose and (i + 1) % 100 == 0:
                        elapsed = time.time() - start_time
                        rate = (i + 1) / elapsed
                        print(f"[*] Progress: {i + 1}/{iterations} | Success: {successful} | Failed: {failed} | Rate: {rate:.1f} iter/sec")
                
                except Exception as e:
                    failed += 1
                    if verbose:
                        print(f"[Iteration {i + 1}] Write failed: {e}")
                    elif (i + 1) % 100 == 0:
                        print(f"[!] Write error at iteration {i + 1}: {e}")
        
        except KeyboardInterrupt:
            print("\n[*] Fuzzing stopped by user")
        
        # Summary
        elapsed = time.time() - start_time
        print("\n" + "=" * 80)
        print("[Fuzzing Summary]")
        print("=" * 80)
        print(f"Characteristic: {uuid}")
        print(f"Total Iterations: {successful + failed}")
        print(f"Successful: {successful}")
        print(f"Failed: {failed}")
        print(f"Time Elapsed: {elapsed:.2f} seconds")
        print(f"Average Rate: {(successful + failed) / elapsed:.1f} iterations/sec")
        print("=" * 80)
    
    async def fuzz_all_characteristics(self, iterations: int = 10000, response: bool = True, read_after_write: bool = True, verbose: bool = False, strategy: str = 'basic'):
        """
        Fuzz all writable characteristics
        
        Args:
            iterations: Number of fuzzing iterations per characteristic (default: 10000)
            response: Whether to wait for write response
            read_after_write: If True, read after write for read/write characteristics
            verbose: If True, print written and read data for each iteration
            strategy: Fuzzing strategy (basic, cmd_injection, format_string, length, tlv, markov, all)
        """
        if not self.client or not self.client.is_connected:
            print("[!] Not connected to any device")
            return
        
        print(f"\n[*] Collecting writable characteristics...")
        
        # Collect all writable characteristics
        read_write_chars = []
        write_only_chars = []
        
        try:
            services = self.client.services
            
            for service in services:
                for char in service.characteristics:
                    properties = char.properties
                    can_read = 'read' in properties
                    can_write = 'write' in properties or 'write-without-response' in properties
                    
                    if can_read and can_write:
                        read_write_chars.append((char.uuid, True))  # True = can read
                    elif can_write:
                        write_only_chars.append((char.uuid, False))  # False = cannot read
            
            total_chars = len(read_write_chars) + len(write_only_chars)
            
            if total_chars == 0:
                print("[!] No writable characteristics found")
                return
            
            print(f"[*] Found {len(read_write_chars)} read/write characteristics")
            print(f"[*] Found {len(write_only_chars)} write-only characteristics")
            print(f"[*] Total: {total_chars} characteristics to fuzz")
            print(f"[*] {iterations} iterations per characteristic")
            print(f"[*] Total operations: {total_chars * iterations}")
            print(f"[*] Press Ctrl+C to stop")
            print("=" * 80)
            
            overall_start = time.time()
            overall_successful = 0
            overall_failed = 0
            
            # Fuzz each characteristic
            for idx, (uuid, can_read) in enumerate(read_write_chars + write_only_chars, 1):
                print(f"\n[*] Fuzzing characteristic {idx}/{total_chars}: {uuid}")
                
                successful = 0
                failed = 0
                start_time = time.time()
                
                try:
                    for i in range(iterations):
                        # Generate fuzz data
                        fuzz_data = self.generate_fuzz_data(strategy=strategy)
                        
                        # Write fuzz data
                        try:
                            if verbose:
                                print(f"\n  [Iteration {i + 1}] Writing {len(fuzz_data)} bytes:")
                                print(f"      {self._format_hex_with_ascii(fuzz_data)}")
                            
                            await self.client.write_gatt_char(uuid, fuzz_data, response=response)
                            successful += 1
                            
                            # Read after write if characteristic supports it
                            if can_read and read_after_write:
                                try:
                                    value = await self.client.read_gatt_char(uuid)
                                    if verbose:
                                        print(f"  [Iteration {i + 1}] Read {len(value)} bytes:")
                                        print(f"      {self._format_hex_with_ascii(value)}")
                                except Exception as e:
                                    if verbose:
                                        print(f"  [Iteration {i + 1}] Read failed: {e}")
                        
                        except Exception as e:
                            failed += 1
                            if verbose:
                                print(f"  [Iteration {i + 1}] Write failed: {e}")
                        
                        # Progress update every 1000 iterations (only in non-verbose mode)
                        if not verbose and (i + 1) % 1000 == 0:
                            elapsed = time.time() - start_time
                            rate = (i + 1) / elapsed
                            print(f"    Progress: {i + 1}/{iterations} | Rate: {rate:.1f} iter/sec")
                
                except KeyboardInterrupt:
                    print(f"\n[*] Fuzzing stopped by user at characteristic {idx}/{total_chars}")
                    overall_successful += successful
                    overall_failed += failed
                    break
                
                overall_successful += successful
                overall_failed += failed
                
                elapsed = time.time() - start_time
                print(f"    Completed: {successful} successful, {failed} failed ({elapsed:.2f}s)")
            
            # Overall summary
            overall_elapsed = time.time() - overall_start
            print("\n" + "=" * 80)
            print("[Overall Fuzzing Summary]")
            print("=" * 80)
            print(f"Characteristics Fuzzed: {idx}")
            print(f"Total Iterations: {overall_successful + overall_failed}")
            print(f"Successful: {overall_successful}")
            print(f"Failed: {overall_failed}")
            print(f"Time Elapsed: {overall_elapsed:.2f} seconds")
            print(f"Average Rate: {(overall_successful + overall_failed) / overall_elapsed:.1f} iterations/sec")
            print("=" * 80)
        
        except Exception as e:
            print(f"[!] Error during fuzzing: {e}")
    
    async def fuzz_write_read_all(self, iterations: int = 10000, verbose: bool = False, strategy: str = 'basic'):
        """
        Write fuzz data to all writable characteristics and read all readable characteristics
        on each iteration (comprehensive state dump)
        
        Args:
            iterations: Number of fuzzing iterations (default: 10000)
            verbose: If True, print written and read data for each iteration
            strategy: Fuzzing strategy (basic, cmd_injection, format_string, length, tlv, markov, all)
        """
        if not self.client or not self.client.is_connected:
            print("[!] Not connected to any device")
            return
        
        print(f"\n[*] Collecting characteristics...")
        
        # Collect characteristics
        writable_chars = []
        readable_chars = []
        
        try:
            services = self.client.services
            
            for service in services:
                for char in service.characteristics:
                    properties = char.properties
                    can_read = 'read' in properties
                    can_write = 'write' in properties or 'write-without-response' in properties
                    
                    if can_write:
                        writable_chars.append(char.uuid)
                    if can_read:
                        readable_chars.append(char.uuid)
            
            if not writable_chars:
                print("[!] No writable characteristics found")
                return
            
            print(f"[*] Found {len(writable_chars)} writable characteristics")
            print(f"[*] Found {len(readable_chars)} readable characteristics")
            print(f"[*] Iterations: {iterations}")
            print(f"[*] Each iteration: write {len(writable_chars)} + read {len(readable_chars)} characteristics")
            print(f"[*] Press Ctrl+C to stop")
            print("=" * 80)
            
            start_time = time.time()
            successful_writes = 0
            failed_writes = 0
            successful_reads = 0
            failed_reads = 0
            
            try:
                for i in range(iterations):
                    if verbose:
                        print(f"\n[Iteration {i + 1}]")
                    
                    # Write to all writable characteristics
                    for uuid in writable_chars:
                        fuzz_data = self.generate_fuzz_data(strategy=strategy)
                        try:
                            if verbose:
                                print(f"  Writing to {uuid} ({len(fuzz_data)} bytes):")
                                print(f"    {self._format_hex_with_ascii(fuzz_data)}")
                            
                            await self.client.write_gatt_char(uuid, fuzz_data, response=False)
                            successful_writes += 1
                        except Exception as e:
                            failed_writes += 1
                            if verbose:
                                print(f"  Write to {uuid} failed: {e}")
                    
                    # Read all readable characteristics
                    for uuid in readable_chars:
                        try:
                            value = await self.client.read_gatt_char(uuid)
                            successful_reads += 1
                            
                            if verbose:
                                print(f"  Read from {uuid} ({len(value)} bytes):")
                                print(f"    {self._format_hex_with_ascii(value)}")
                        except Exception as e:
                            failed_reads += 1
                            if verbose:
                                print(f"  Read from {uuid} failed: {e}")
                    
                    # Progress update (only in non-verbose mode)
                    if not verbose and (i + 1) % 100 == 0:
                        elapsed = time.time() - start_time
                        rate = (i + 1) / elapsed
                        print(f"[*] Iteration {i + 1}/{iterations} | Writes: {successful_writes} | Reads: {successful_reads} | Rate: {rate:.1f} iter/sec")
            
            except KeyboardInterrupt:
                print("\n[*] Fuzzing stopped by user")
            
            # Summary
            elapsed = time.time() - start_time
            total_iterations = successful_writes // len(writable_chars) if writable_chars else 0
            
            print("\n" + "=" * 80)
            print("[Write-All/Read-All Fuzzing Summary]")
            print("=" * 80)
            print(f"Iterations Completed: {total_iterations}")
            print(f"Writable Characteristics: {len(writable_chars)}")
            print(f"Readable Characteristics: {len(readable_chars)}")
            print(f"Successful Writes: {successful_writes}")
            print(f"Failed Writes: {failed_writes}")
            print(f"Successful Reads: {successful_reads}")
            print(f"Failed Reads: {failed_reads}")
            print(f"Time Elapsed: {elapsed:.2f} seconds")
            print(f"Average Rate: {total_iterations / elapsed:.1f} iterations/sec")
            print("=" * 80)
        
        except Exception as e:
            print(f"[!] Error during fuzzing: {e}")


async def interactive_mode():
    """Interactive mode for the fuzzer"""
    fuzzer = BLEFuzzer()
    
    print("=" * 80)
    print("GaBL-E: BLE Fuzzer")
    print("=" * 80)
    
    while True:
        # Check connection status
        is_connected = fuzzer.client and fuzzer.client.is_connected
        
        # Display menu based on connection status
        if is_connected:
            print(f"\n[Menu - Connected to {fuzzer.selected_device}]")
        else:
            print("\n[Menu - Not Connected]")
        
        print("1. Scan for BLE devices (short)")
        print("2. Scan for BLE devices (verbose)")
        
        if is_connected:
            print("3. Disconnect")
            print("4. Enumerate characteristics")
            print("5. Read characteristic")
            print("6. Write characteristic")
            print("7. Fuzz single characteristic")
            print("8. Fuzz all writable characteristics")
            print("9. Fuzz write-all/read-all")
        else:
            print("3. Connect to device by UUID")
        
        print("0. Exit")
        
        # Show appropriate prompt
        if is_connected:
            choice = input("\nconnected> ").strip()
        else:
            choice = input("\n> ").strip()
        
        if choice == '1':
            duration = input("Scan duration (seconds, default=5): ").strip()
            duration = int(duration) if duration else 5
            await fuzzer.scan_devices(verbose=False, duration=duration)
        
        elif choice == '2':
            duration = input("Scan duration (seconds, default=5): ").strip()
            duration = int(duration) if duration else 5
            await fuzzer.scan_devices(verbose=True, duration=duration)
        
        elif choice == '3':
            if is_connected:
                # Disconnect
                await fuzzer.disconnect()
            else:
                # Connect
                address = input("Enter device UUID: ").strip()
                await fuzzer.connect_device(address)
        
        elif choice == '4':
            if is_connected:
                await fuzzer.enumerate_characteristics()
            else:
                print("[!] Not connected. Use option 3 to connect first.")
        
        elif choice == '5':
            if is_connected:
                uuid = input("Enter characteristic UUID (or * for all): ").strip()
                await fuzzer.read_characteristic(uuid)
            else:
                print("[!] Not connected. Use option 3 to connect first.")
        
        elif choice == '6':
            if is_connected:
                uuid = input("Enter characteristic UUID: ").strip()
                data_hex = input("Enter data (hex): ").strip()
                response = input("Wait for response? (y/n, default=y): ").strip().lower()
                response = response != 'n'
                
                try:
                    data = bytes.fromhex(data_hex)
                    await fuzzer.write_characteristic(uuid, data, response)
                except ValueError:
                    print("[!] Invalid hex data")
            else:
                print("[!] Not connected. Use option 3 to connect first.")
        
        elif choice == '7':
            if is_connected:
                uuid = input("Enter characteristic UUID to fuzz: ").strip()
                iterations = input("Number of iterations (default=10000): ").strip()
                iterations = int(iterations) if iterations else 10000
                
                print("\nFuzzing Strategies:")
                print("  1. Basic (random patterns)")
                print("  2. Command Injection")
                print("  3. Format String")
                print("  4. Length Attacks")
                print("  5. TLV Malformed")
                print("  6. Markov Chain")
                print("  7. All (random mix)")
                strategy_choice = input("Select strategy (default=1): ").strip()
                strategy_map = {
                    '1': 'basic', '2': 'cmd_injection', '3': 'format_string',
                    '4': 'length', '5': 'tlv', '6': 'markov', '7': 'all'
                }
                strategy = strategy_map.get(strategy_choice, 'basic')
                
                read_after = input("Read after write? (y/n, default=n): ").strip().lower()
                read_after = read_after == 'y'
                
                verbose = input("Verbose output (show data for each iteration)? (y/n, default=n): ").strip().lower()
                verbose = verbose == 'y'
                
                await fuzzer.fuzz_characteristic(uuid, iterations=iterations, response=False, read_after_write=read_after, verbose=verbose, strategy=strategy)
            else:
                print("[!] Not connected. Use option 3 to connect first.")
        
        elif choice == '8':
            if is_connected:
                iterations = input("Number of iterations per characteristic (default=10000): ").strip()
                iterations = int(iterations) if iterations else 10000
                
                print("\nFuzzing Strategies:")
                print("  1. Basic (random patterns)")
                print("  2. Command Injection")
                print("  3. Format String")
                print("  4. Length Attacks")
                print("  5. TLV Malformed")
                print("  6. Markov Chain")
                print("  7. All (random mix)")
                strategy_choice = input("Select strategy (default=1): ").strip()
                strategy_map = {
                    '1': 'basic', '2': 'cmd_injection', '3': 'format_string',
                    '4': 'length', '5': 'tlv', '6': 'markov', '7': 'all'
                }
                strategy = strategy_map.get(strategy_choice, 'basic')
                
                read_after = input("Read after write for read/write characteristics? (y/n, default=y): ").strip().lower()
                read_after = read_after != 'n'
                
                verbose = input("Verbose output (show data for each iteration)? (y/n, default=n): ").strip().lower()
                verbose = verbose == 'y'
                
                await fuzzer.fuzz_all_characteristics(iterations=iterations, response=False, read_after_write=read_after, verbose=verbose, strategy=strategy)
            else:
                print("[!] Not connected. Use option 3 to connect first.")
        
        elif choice == '9':
            if is_connected:
                iterations = input("Number of iterations (default=10000): ").strip()
                iterations = int(iterations) if iterations else 10000
                
                print("\nFuzzing Strategies:")
                print("  1. Basic (random patterns)")
                print("  2. Command Injection")
                print("  3. Format String")
                print("  4. Length Attacks")
                print("  5. TLV Malformed")
                print("  6. Markov Chain")
                print("  7. All (random mix)")
                strategy_choice = input("Select strategy (default=1): ").strip()
                strategy_map = {
                    '1': 'basic', '2': 'cmd_injection', '3': 'format_string',
                    '4': 'length', '5': 'tlv', '6': 'markov', '7': 'all'
                }
                strategy = strategy_map.get(strategy_choice, 'basic')
                
                verbose = input("Verbose output (show data for each iteration)? (y/n, default=n): ").strip().lower()
                verbose = verbose == 'y'
                
                await fuzzer.fuzz_write_read_all(iterations=iterations, verbose=verbose, strategy=strategy)
            else:
                print("[!] Not connected. Use option 3 to connect first.")
        
        elif choice == '0':
            if fuzzer.client and fuzzer.client.is_connected:
                await fuzzer.disconnect()
            print("[*] Exiting...")
            break
        
        else:
            print("[!] Invalid option")


async def main():
    parser = argparse.ArgumentParser(
        description="GaBL-E: BLE Fuzzer for macOS - Bluetooth Low Energy Security Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan for devices (short format with name, UUID, RSSI)
  %(prog)s --scan
  
  # Scan with detailed information (service data, manufacturer data, etc.)
  %(prog)s --scan --verbose --duration 10
  
  # Connect to device and enumerate all characteristics (shows READ/WRITE capabilities)
  # Note: Use the UUID from scan results
  %(prog)s --mac 12345678-ABCD-1234-ABCD-123456789ABC --enumerate
  
  # Fuzz a specific characteristic with 5000 iterations
  %(prog)s --mac <UUID> --fuzz-char 0000abcd-0000-1000-8000-00805f9b34fb --iterations 5000
  
  # Fuzz with command injection strategy
  %(prog)s --mac <UUID> --fuzz-char <CHAR_UUID> --strategy cmd_injection --iterations 1000
  
  # Fuzz with format string attacks
  %(prog)s --mac <UUID> --fuzz-char <CHAR_UUID> --strategy format_string --iterations 500
  
  # Fuzz with length attacks (very long strings)
  %(prog)s --mac <UUID> --fuzz-char <CHAR_UUID> --strategy length --iterations 100
  
  # Fuzz with malformed TLV structures
  %(prog)s --mac <UUID> --fuzz-char <CHAR_UUID> --strategy tlv --iterations 1000
  
  # Fuzz with Markov chain data
  %(prog)s --mac <UUID> --fuzz-char <CHAR_UUID> --strategy markov --iterations 5000
  
  # Fuzz with all strategies (random mix)
  %(prog)s --mac <UUID> --fuzz-all --strategy all --iterations 10000
  
  # Fuzz with verbose output (shows written/read data in hexdump format)
  %(prog)s --mac <UUID> --fuzz-char 0000abcd-0000-1000-8000-00805f9b34fb --iterations 100 --verbose-fuzz
  
  # Fuzz all writable characteristics (10000 iterations per characteristic)
  %(prog)s --mac <UUID> --fuzz-all --iterations 10000
  
  # Write to all writable and read all readable characteristics (comprehensive state dump)
  %(prog)s --mac <UUID> --fuzz-write-read-all --iterations 1000
  
  # Verbose fuzzing with read-after-write
  %(prog)s --mac <UUID> --fuzz-char <CHAR_UUID> --read-after-write --verbose-fuzz --iterations 50
  
  # Interactive mode (menu-driven with all features including fuzzing)
  %(prog)s --interactive

Workflow:
  1. Scan for devices to find UUIDs: --scan [--verbose]
  2. Connect and explore: --mac <UUID> --enumerate
  3. Use interactive mode for read/write/fuzz operations: --interactive
  4. Or use CLI fuzzing: --mac <UUID> --fuzz-char/--fuzz-all/--fuzz-write-read-all

Note: 
  - macOS uses UUIDs instead of MAC addresses for BLE devices
  - Enumeration requires connection (use --mac with --enumerate)
  - Fuzzing requires connection and a characteristic UUID
  - Press Ctrl+C to stop fuzzing at any time
"""
    )
    
    parser.add_argument(
        '-s', '--scan',
        action='store_true',
        help='Scan for BLE devices in range'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information during scan (service data, manufacturer data, etc.)'
    )
    
    parser.add_argument(
        '-d', '--duration',
        type=int,
        default=5,
        metavar='SECONDS',
        help='How long to scan for devices (default: 5 seconds)'
    )
    
    parser.add_argument(
        '-m', '--mac',
        type=str,
        metavar='UUID',
        help='Device UUID to connect to (get from --scan results)'
    )
    
    parser.add_argument(
        '-e', '--enumerate',
        action='store_true',
        help='Enumerate all services and characteristics after connecting (requires --mac)'
    )
    
    parser.add_argument(
        '-i', '--interactive',
        action='store_true',
        help='Start interactive menu mode for step-by-step operations'
    )
    
    # Fuzzing arguments
    parser.add_argument(
        '--fuzz-char',
        type=str,
        metavar='UUID',
        help='Fuzz a specific characteristic UUID (requires --mac)'
    )
    
    parser.add_argument(
        '--fuzz-all',
        action='store_true',
        help='Fuzz all writable characteristics (requires --mac)'
    )
    
    parser.add_argument(
        '--fuzz-write-read-all',
        action='store_true',
        help='Write to all writable and read all readable characteristics each iteration (requires --mac)'
    )
    
    parser.add_argument(
        '--iterations',
        type=int,
        default=10000,
        metavar='N',
        help='Number of fuzzing iterations (default: 10000)'
    )
    
    parser.add_argument(
        '--read-after-write',
        action='store_true',
        help='Read characteristic after writing (for --fuzz-char and --fuzz-all)'
    )
    
    parser.add_argument(
        '--verbose-fuzz',
        action='store_true',
        help='Show written and read data for each fuzzing iteration (hex and ASCII)'
    )
    
    parser.add_argument(
        '--strategy',
        type=str,
        choices=['basic', 'cmd_injection', 'format_string', 'length', 'tlv', 'markov', 'all'],
        default='basic',
        help='Fuzzing strategy: basic (random patterns), cmd_injection, format_string, length, tlv, markov, all (default: basic)'
    )
    
    args = parser.parse_args()
    
    # Validate argument combinations
    if args.enumerate and not args.mac:
        parser.error("--enumerate requires --mac <UUID> to connect to a device first.\nUse --scan to find device UUIDs.")
    
    if args.fuzz_char and not args.mac:
        parser.error("--fuzz-char requires --mac <UUID> to connect to a device first.")
    
    if args.fuzz_all and not args.mac:
        parser.error("--fuzz-all requires --mac <UUID> to connect to a device first.")
    
    if args.fuzz_write_read_all and not args.mac:
        parser.error("--fuzz-write-read-all requires --mac <UUID> to connect to a device first.")
    
    # Check for conflicting fuzzing options
    fuzz_options = sum([bool(args.fuzz_char), args.fuzz_all, args.fuzz_write_read_all])
    if fuzz_options > 1:
        parser.error("Only one fuzzing mode can be used at a time: --fuzz-char, --fuzz-all, or --fuzz-write-read-all")
    
    fuzzer = BLEFuzzer()
    
    try:
        if args.interactive:
            await interactive_mode()
        else:
            if args.scan:
                await fuzzer.scan_devices(verbose=args.verbose, duration=args.duration)
            
            if args.mac:
                connected = await fuzzer.connect_device(args.mac)
                
                if connected and args.enumerate:
                    await fuzzer.enumerate_characteristics()
                    await fuzzer.disconnect()
                
                elif connected and args.fuzz_char:
                    print(f"\n[*] Fuzzing characteristic: {args.fuzz_char}")
                    print(f"[*] Strategy: {args.strategy}")
                    await fuzzer.fuzz_characteristic(
                        args.fuzz_char,
                        iterations=args.iterations,
                        response=False,
                        read_after_write=args.read_after_write,
                        verbose=args.verbose_fuzz,
                        strategy=args.strategy
                    )
                    await fuzzer.disconnect()
                
                elif connected and args.fuzz_all:
                    print(f"\n[*] Fuzzing all writable characteristics")
                    print(f"[*] Strategy: {args.strategy}")
                    await fuzzer.fuzz_all_characteristics(
                        iterations=args.iterations,
                        response=False,
                        read_after_write=args.read_after_write,
                        verbose=args.verbose_fuzz,
                        strategy=args.strategy
                    )
                    await fuzzer.disconnect()
                
                elif connected and args.fuzz_write_read_all:
                    print(f"\n[*] Fuzzing with write-all/read-all mode")
                    print(f"[*] Strategy: {args.strategy}")
                    await fuzzer.fuzz_write_read_all(
                        iterations=args.iterations,
                        verbose=args.verbose_fuzz,
                        strategy=args.strategy
                    )
                    await fuzzer.disconnect()
                
                elif connected and not args.enumerate:
                    print("\n[*] Connected successfully!")
                    print("[*] Tip: Use --enumerate to list all characteristics, or --interactive for more options")
                    await fuzzer.disconnect()
            
            elif not args.scan and not args.interactive:
                # No action specified, show help
                parser.print_help()
    
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
        if fuzzer.client and fuzzer.client.is_connected:
            await fuzzer.disconnect()
    
    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
