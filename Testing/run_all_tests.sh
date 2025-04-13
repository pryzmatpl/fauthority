#!/bin/bash

set -e  # Exit on any error

echo "Setting up test environment..."
./Testing/setup_test_env.sh

echo "Building the project..."
./build.sh

echo "Running all tests..."
cd build && ctest --verbose

echo "Tests completed successfully!" 