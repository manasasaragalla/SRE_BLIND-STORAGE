#include "crypto/aes_gcm.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <climits>
#include <memory>
#include <stdexcept>

namespace crypto {

namespace {

constexpr int KEY_SIZE = 32;
constexpr int NONCE_SIZE = 12;
constexpr int TAG_SIZE = 16;

using CipherContext =
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

}  // namespace

Ciphertext aes_gcm_encrypt(
    const Key256& key,
    const std::vector<unsigned char>& plaintext
) {
    if (plaintext.size() > static_cast<std::size_t>(INT_MAX)) {
        throw std::invalid_argument("Plaintext is too large");
    }

    Ciphertext result;
    result.nonce.resize(NONCE_SIZE);
    result.encrypted_data.resize(plaintext.size());
    result.tag.resize(TAG_SIZE);

    if (RAND_bytes(result.nonce.data(), NONCE_SIZE) != 1) {
        throw std::runtime_error("Nonce generation failed");
    }

    CipherContext ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    if (!ctx ||
        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr,
                           nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            NONCE_SIZE, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
                           key.data(), result.nonce.data()) != 1) {
        throw std::runtime_error("AES-GCM initialization failed");
    }

    int written = 0;
    int total_written = 0;

    if (!plaintext.empty() &&
        EVP_EncryptUpdate(ctx.get(), result.encrypted_data.data(),
                          &written, plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1) {
        throw std::runtime_error("AES-GCM encryption failed");
    }

    total_written += written;

    if (EVP_EncryptFinal_ex(
            ctx.get(),
            result.encrypted_data.data() + total_written,
            &written) != 1) {
        throw std::runtime_error("AES-GCM finalization failed");
    }

    total_written += written;
    result.encrypted_data.resize(total_written);

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                            TAG_SIZE, result.tag.data()) != 1) {
        throw std::runtime_error("Failed to retrieve authentication tag");
    }

    return result;
}

std::vector<unsigned char> aes_gcm_decrypt(
    const Key256& key,
    const Ciphertext& ciphertext
) {
    if (ciphertext.nonce.size() != NONCE_SIZE ||
        ciphertext.tag.size() != TAG_SIZE ||
        ciphertext.encrypted_data.size() >
            static_cast<std::size_t>(INT_MAX)) {
        throw std::invalid_argument("Invalid AES-GCM ciphertext format");
    }

    std::vector<unsigned char> plaintext(ciphertext.encrypted_data.size());

    CipherContext ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    if (!ctx ||
        EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr,
                           nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            NONCE_SIZE, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
                           key.data(), ciphertext.nonce.data()) != 1) {
        throw std::runtime_error("AES-GCM initialization failed");
    }

    int written = 0;
    int total_written = 0;

    if (!ciphertext.encrypted_data.empty() &&
        EVP_DecryptUpdate(
            ctx.get(), plaintext.data(), &written,
            ciphertext.encrypted_data.data(),
            static_cast<int>(ciphertext.encrypted_data.size())) != 1) {
        throw std::runtime_error("AES-GCM decryption failed");
    }

    total_written += written;

    // Set the expected authentication tag before final verification.
    if (EVP_CIPHER_CTX_ctrl(
            ctx.get(), EVP_CTRL_GCM_SET_TAG,
            TAG_SIZE,
            const_cast<unsigned char*>(ciphertext.tag.data())) != 1) {
        throw std::runtime_error("Failed to set authentication tag");
    }

    if (EVP_DecryptFinal_ex(
            ctx.get(), plaintext.data() + total_written, &written) != 1) {
        throw std::runtime_error(
            "Authentication failed: ciphertext may have been modified"
        );
    }

    total_written += written;
    plaintext.resize(total_written);

    return plaintext;
}

}  // namespace crypto