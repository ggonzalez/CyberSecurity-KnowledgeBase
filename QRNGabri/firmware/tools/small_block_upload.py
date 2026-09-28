# PlatformIO post-script: route esptool uploads through esptool_small_blocks.py.
# See that file for why (CH343 + macOS built-in driver drops large transfers).
import os

Import("env")

env["ENV"]["PIO_ESPTOOL_DIR"] = env.PioPlatform().get_package_dir("tool-esptoolpy")
env.Replace(UPLOADER=os.path.join(env.subst("$PROJECT_DIR"), "tools", "esptool_small_blocks.py"))
