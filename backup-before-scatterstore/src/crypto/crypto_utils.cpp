#include "crypto/crypto_utils.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>

namespace crypto {

Key256 generate_key() {
    Key256 key{};

    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
        throw std::runtime_error("Failed to generate cryptographic key");
    }

    return key;
}

std::vector<unsigned char> random_bytes(std::size_t size) {
    if (size > static_cast<std::size_t>(INT_MAX)) {
        throw std::invalid_argument("Requested random byte count is too large");
    }

    std::vector<unsigned char> bytes(size);

    if (size > 0 &&
        RAND_bytes(bytes.data(), static_cast<int>(size)) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }

    return bytes;
}

Hash256 sha256(const std::vector<unsigned char>& data) {
    Hash256 digest{};
    unsigned int digest_size = 0;

    using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    Context context(EVP_MD_CTX_new(), EVP_MD_CTX_free);

    if (!context ||
        EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(context.get(), data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(context.get(), digest.data(), &digest_size) != 1 ||
        digest_size != digest.size()) {
        throw std::runtime_error("SHA-256 computation failed");
    }

    return digest;
}

Hash256 hmac_sha256(
    const Key256& key,
    const std::vector<unsigned char>& data
) {
    Hash256 digest{};
    unsigned int digest_size = 0;

    if (HMAC(
            EVP_sha256(),
            key.data(),
            static_cast<int>(key.size()),
            data.data(),
            data.size(),
            digest.data(),
            &digest_size
        ) == nullptr ||
        digest_size != digest.size()) {
        throw std::runtime_error("HMAC-SHA-256 computation failed");
    }

    return digest;
}

std::string to_hex(const unsigned char* data, std::size_t size) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');

    for (std::size_t i = 0; i < size; ++i) {
        output << std::setw(2) << static_cast<unsigned int>(data[i]);
    }

    return output.str();
}

}  // namespace crypto