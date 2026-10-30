#ifndef BLOCK_CRYPTO_H
#define BLOCK_CRYPTO_H

#include "crypto/crypto_utils.h"
#include "storage/storage_block.h"

namespace storage {

// Encrypts or decrypts a block using the paper's XOR-mask construction.
// The version number stays unencrypted.
void crypt_block(
    StorageBlock& block,
    const crypto::Key256& key
);

}  // namespace storage

#endif