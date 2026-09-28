"""
esptool wrapper that writes flash in small blocks.

The board's CH343 USB-serial bridge, when served by macOS's built-in CDC
driver, corrupts larger USB transfers: the esptool stub (6 KB RAM blocks) and
the ROM loader's default 1 KB flash blocks both fail at seq 0, while 256-byte
blocks go through reliably. Use together with --no-stub.

Block size can be overridden with ESPTOOL_FLASH_BLOCK (bytes).
"""
import os
import sys

sys.path.insert(0, os.environ["PIO_ESPTOOL_DIR"])

import esptool  # noqa: E402
from esptool.targets.esp32s3 import ESP32S3ROM  # noqa: E402

ESP32S3ROM.FLASH_WRITE_SIZE = int(os.environ.get("ESPTOOL_FLASH_BLOCK", "256"))

esptool._main()
