import os
from PyInstaller.utils.hooks import collect_dynamic_libs

oqs_dll = os.path.join(os.path.expanduser("~"), "_oqs", "bin", "liboqs.dll")

a = Analysis(
    ["main.py"],
    pathex=["."],
    binaries=[(oqs_dll, ".")] + collect_dynamic_libs("cryptography"),
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
