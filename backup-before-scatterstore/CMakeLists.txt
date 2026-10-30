cmake_minimum_required(VERSION 3.20)

project(BlindStorageProject
    VERSION 1.0.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_executable(blind_storage
     src/main.cpp
    src/crypto/crypto_utils.cpp
    src/crypto/aes_gcm.cpp
    src/crypto/aes_prf.cpp
    src/crypto/hash_utils.cpp
    src/storage/storage_block.cpp
    src/storage/block_crypto.cpp
    src/storage/block_store.cpp
    src/storage/file_manager.cpp
)

target_link_libraries(blind_storage PRIVATE OpenSSL::Crypto)
target_include_directories(blind_storage PRIVATE include)
target_compile_options(blind_storage PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)