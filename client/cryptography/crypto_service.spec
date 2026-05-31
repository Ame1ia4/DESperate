import os
import sys
from PyInstaller.utils.hooks import collect_dynamic_libs

if sys.platform == "win32":
    liboqs_lib = os.path.join(os.path.expanduser("~"), "_oqs", "bin", "liboqs.dll")
else:
    liboqs_lib = os.path.join(os.path.expanduser("~"), "_oqs", "lib", "liboqs.so")

if not os.path.exists(liboqs_lib):
    raise FileNotFoundError(
        f"liboqs shared library not found at {liboqs_lib}.\n"
        "Build liboqs first with prefix=~/_oqs, then re-run PyInstaller."
    )

a = Analysis(
    ["main.py"],
    pathex=["."],
    binaries=[(liboqs_lib, ".")] + collect_dynamic_libs("cryptography"),
    datas=[],
    hiddenimports=["oqs", "argon2", "cryptography"],
    hookspath=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name="crypto_service",
    console=False,
    upx=False,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    name="crypto_service",
)
