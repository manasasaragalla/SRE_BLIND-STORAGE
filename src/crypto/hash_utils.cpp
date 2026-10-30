#include "crypto/hash_utils.h"

#include <openssl/evp.h>

#include <memory>
#include <stdexcept>

namespace crypto {

Hash256 sha256(const std::string& input) {
    Hash256 hash{};

    using ContextPtr = std::unique_ptr<
        EVP_MD_CTX,
        decltype(&EVP_MD_CTX_free)
    >;

    ContextPtr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);

    if (!context) {
        throw std::runtime_error("Failed to create SHA-256 context");
    }

    if (EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("Failed to initialize SHA-256");
    }

    if (EVP_DigestUpdate(
            context.get(), input.data(), input.size()) != 1) {
        throw std::runtime_error("Failed to update SHA-256");
    }

    unsigned int hash_length = 0;

    if (EVP_DigestFinal_ex(
            context.get(), hash.data(), &hash_length) != 1) {
        throw std::runtime_error("Failed to compute SHA-256");
    }

    if (hash_length != hash.size()) {
        throw std::runtime_error("Unexpected SHA-256 output length");
    }

    return hash;
}

}  // namespace crypto