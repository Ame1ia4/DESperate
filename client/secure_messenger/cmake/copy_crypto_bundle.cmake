# copy_crypto_bundle.cmake
# Called as a post-build step. Copies the PyInstaller crypto_service bundle
# next to the Qt binary, with a clear error if it hasn't been built yet.
#
# Required variables (passed via -D):
#   SRC_DIR  — path to dist/crypto_service/
#   DST_DIR  — destination inside the build output directory

if(WIN32)
    set(_EXE "crypto_service.exe")
else()
    set(_EXE "crypto_service")
endif()

if(NOT EXISTS "${SRC_DIR}/${_EXE}")
    if(WIN32)
        set(_BUILD_INSTRUCTIONS
            " PowerShell:\n"
            "   cd client/cryptography\n"
            "   \$env:PATH = 'C:\\Qt\\Tools\\CMake_64\\bin;C:\\Qt\\Tools\\mingw1310_64\\bin;' + \$env:PATH\n"
            "   \$env:CMAKE_GENERATOR = 'MinGW Makefiles'\n"
            "   pip install -r requirements.txt\n"
            "   pip install pyinstaller\n"
            "   python -m PyInstaller crypto_service.spec\n"
            "\n"
            " Git Bash / MSYS2:\n"
            "   cd client/cryptography\n"
            "   export PATH=/c/Qt/Tools/CMake_64/bin:/c/Qt/Tools/mingw1310_64/bin:\$PATH\n"
            "   export CMAKE_GENERATOR='MinGW Makefiles'\n"
            "   pip install -r requirements.txt && pip install pyinstaller\n"
            "   python -m PyInstaller crypto_service.spec\n"
        )
    else()
        set(_BUILD_INSTRUCTIONS
            "   cd client/cryptography\n"
            "   pip install -r requirements.txt && pip install pyinstaller\n"
            "   python -m PyInstaller crypto_service.spec\n"
        )
    endif()

    # In development (Debug builds) warn and skip the copy rather than failing.
    # The Qt app will connect to a manually-started Python service on port 54231.
    # For release/distribution builds you MUST build the bundle first.
    message(WARNING
        "\n"
        "===========================================================\n"
        " crypto_service bundle not found — skipping copy step.\n"
        "===========================================================\n"
        "\n"
        " Expected: ${SRC_DIR}/${_EXE}\n"
        "\n"
        " DEV MODE: Start the Python crypto service manually before\n"
        " running the Qt app:\n"
        "   cd client/cryptography && python main.py\n"
        "\n"
        " For a distributable build, compile the bundle first:\n"
        ${_BUILD_INSTRUCTIONS}
        "\n"
        " See README.md § Cryptography Microservice for details.\n"
        "===========================================================\n"
    )
    return()   # skip the copy — the app will still build and link
endif()

file(COPY "${SRC_DIR}/" DESTINATION "${DST_DIR}")
message(STATUS "crypto_service bundle copied to ${DST_DIR}")
