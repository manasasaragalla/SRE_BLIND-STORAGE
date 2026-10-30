#ifndef AES_GCM_H
#define AES_GCM_H

#include "crypto/crypto_utils.h"

#include <vector>

namespace crypto {

struct Ciphertext {
    std::vector<unsigned char> nonce;
    std::vector<unsigned char> encrypted_data;
    std::vector<unsigned char> tag;
};

// Encrypt plaintext using AES-256-GCM.
Ciphertext aes_gcm_encrypt(
    const Key256& key,
    const std::vector<unsigned char>& plaintext
);

// Decrypt and authenticate AES-256-GCM ciphertext.
// Throws an exception if authentication fails.
std::vector<unsigned char> aes_gcm_decrypt(
    const Key256& key,
    const Ciphertext& ciphertext
);

}  // namespace crypto

#endif