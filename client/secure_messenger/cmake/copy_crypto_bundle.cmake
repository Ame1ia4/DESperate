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

    message(FATAL_ERROR
        "\n"
        "===========================================================\n"
        " crypto_service bundle not found.\n"
        "===========================================================\n"
        "\n"
        " Expected: ${SRC_DIR}/${_EXE}\n"
        "\n"
        " You need to build the Python crypto service first.\n"
        " Run these commands from the repo root:\n"
        "\n"
        ${_BUILD_INSTRUCTIONS}
        "\n"
        " Then rebuild the Qt project in Qt Creator.\n"
        " See README.md § Cryptography Microservice for details.\n"
        "===========================================================\n"
    )
endif()

file(COPY "${SRC_DIR}/" DESTINATION "${DST_DIR}")
message(STATUS "crypto_service bundle copied to ${DST_DIR}")
