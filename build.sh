#!/bin/bash
cppship build
sed -i 'target_link_libraries/ s/openssl::openssl/OpenSSL::SSL OpenSSL::Crypto)' ./build/CMakeLists.txt
cmake --build ./build
cd build && make