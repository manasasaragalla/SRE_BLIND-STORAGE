#include "crypto/aes_prf.h"

#include <openssl/evp.h>

#include <memory>
#include <stdexcept>

namespace crypto {

namespace {

using CipherContext =
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

}  // namespace

PrfOutput aes_prf_block(
    const Key256& key,
    const std::array<unsigned char, 16>& input
) {
    PrfOutput output{};

    CipherContext ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    if (!ctx ||
        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_ecb(),
                           nullptr, key.data(), nullptr) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1) {
        throw std::runtime_error("AES PRF initialization failed");
    }

    int written = 0;
    int final_written = 0;

    if (EVP_EncryptUpdate(ctx.get(), output.data(), &written,
                          input.data(),
                          static_cast<int>(input.size())) != 1 ||
        EVP_EncryptFinal_ex(ctx.get(), output.data() + written,
                            &final_written) != 1 ||
        written + final_written != static_cast<int>(output.size())) {
        throw std::runtime_error("AES PRF evaluation failed");
    }

    return output;
}

}  // namespace crypto