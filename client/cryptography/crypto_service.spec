import importlib.util
import os
import sys
from PyInstaller.utils.hooks import collect_dynamic_libs

# ── Locate liboqs shared library ──────────────────────────────────────────────
# Priority 1: custom build at ~/_oqs  (used in CI and release builds)
# Priority 2: the DLL bundled inside the pip-installed liboqs-python wheel
#             (pip install liboqs-python includes a pre-built liboqs.dll)

if sys.platform == "win32":
    _custom = os.path.join(os.path.expanduser("~"), "_oqs", "bin", "liboqs.dll")
    if os.path.exists(_custom):
        liboqs_lib = _custom
    else:
        # Find liboqs.dll from the installed oqs package
        _spec = importlib.util.find_spec("oqs")
        if _spec and _spec.origin:
            _pkg_dir = os.path.dirname(_spec.origin)
            _wheel_dll = os.path.join(_pkg_dir, "liboqs.dll")
            if os.path.exists(_wheel_dll):
                liboqs_lib = _wheel_dll
            else:
                raise FileNotFoundError(
                    f"liboqs.dll not found.\n"
                    f"Tried: {_custom}\n"
                    f"Tried: {_wheel_dll}\n"
                    "Install liboqs-python (pip install liboqs-python) or\n"
                    "build liboqs from source with prefix=~/_oqs."
                )
        else:
            raise FileNotFoundError(
                f"liboqs.dll not found at {_custom} and oqs package is not installed.\n"
                "Run: pip install liboqs-python"
            )
else:
    _custom = os.path.join(os.path.expanduser("~"), "_oqs", "lib", "liboqs.so")
    if os.path.exists(_custom):
        liboqs_lib = _custom
    else:
        _spec = importlib.util.find_spec("oqs")
        if _spec and _spec.origin:
            _pkg_dir = os.path.dirname(_spec.origin)
            for _name in ("liboqs.so", "liboqs.so.0"):
                _wheel_so = os.path.join(_pkg_dir, _name)
                if os.path.exists(_wheel_so):
                    liboqs_lib = _wheel_so
                    break
            else:
                raise FileNotFoundError(
                    f"liboqs shared library not found.\n"
                    "Install liboqs-python (pip install liboqs-python) or\n"
                    "build liboqs from source with prefix=~/_oqs."
                )
        else:
            raise FileNotFoundError(
                "liboqs shared library not found and oqs package is not installed.\n"
                "Run: pip install liboqs-python"
            )

# ── PyInstaller analysis ──────────────────────────────────────────────────────

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
