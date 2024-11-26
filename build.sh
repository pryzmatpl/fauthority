#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Detect platform
PLATFORM=$(uname | tr '[:upper:]' '[:lower:]')

# Function to handle sed compatibility
function platform_sed() {
  if [[ "$PLATFORM" == "darwin" ]]; then
    sed -i.bak "$@"  # macOS requires a backup suffix
  else
    sed -i "$@"      # Linux/WSL
  fi
}

# Function to check if a command exists
function check_command() {
  if ! command -v "$1" &>/dev/null; then
    echo "Error: '$1' is not installed or not in PATH. Please install it and try again."
    exit 1
  fi
}

# Check dependencies
check_command cppship
check_command cmake

echo "cppship:"
cppship build & wait || true

echo "sed openssl:"

platform_sed 's/module-OpenSSL/OpenSSL/' ./build/CMakeLists.txt
platform_sed 's/target_link_libraries(fuckauthority_deps INTERFACE openssl::openssl)/target_link_libraries(fuckauthority_deps INTERFACE OpenSSL::SSL OpenSSL::Crypto)/' ./build/CMakeLists.txt

echo "cmake:"
cd ./build && cmake ./ || { echo "CMake configuration failed."; exit 1; }

echo "build:"
cmake --build ./ || { echo "Build failed."; exit 1; }

echo "Build complete."
