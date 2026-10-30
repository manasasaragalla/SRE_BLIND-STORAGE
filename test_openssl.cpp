#include <iostream>
#include <openssl/evp.h>
#include <openssl/crypto.h>

int main() {
    std::cout << "OpenSSL version: " << OpenSSL_version(OPENSSL_VERSION)
              << '\n';
    std::cout << "SHA-256 digest size: "
              << EVP_MD_get_size(EVP_sha256()) << " bytes\n";
    return 0;
}
