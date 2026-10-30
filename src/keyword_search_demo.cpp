#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using Key = std::array<unsigned char, 32>;
using Token = std::array<unsigned char, 32>;

struct EncryptedDocument {
    std::string id;
    std::array<unsigned char, 12> nonce{};
    std::array<unsigned char, 16> tag{};
    std::vector<unsigned char> ciphertext;
};

std::string to_hex(const unsigned char* data, std::size_t size) {
    static const char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(size * 2);

    for (std::size_t i = 0; i < size; ++i) {
        result.push_back(digits[data[i] >> 4]);
        result.push_back(digits[data[i] & 0x0f]);
    }

    return result;
}

Token make_token(const Key& key, const std::string& word) {
    Token token{};
    unsigned int output_length = 0;

    if (HMAC(EVP_sha256(), key.data(),
             static_cast<int>(key.size()),
             reinterpret_cast<const unsigned char*>(word.data()),
             word.size(), token.data(), &output_length) == nullptr ||
        output_length != token.size()) {
        throw std::runtime_error("Keyword-token generation failed");
    }

    return token;
}

std::vector<std::string> tokenize(const std::string& text) {
    std::vector<std::string> words;
    std::string word;

    for (unsigned char ch : text) {
        if (std::isalnum(ch)) {
            word.push_back(static_cast<char>(std::tolower(ch)));
        } else if (!word.empty()) {
            words.push_back(word);
            word.clear();
        }
    }

    if (!word.empty()) {
        words.push_back(word);
    }

    return words;
}

EncryptedDocument encrypt_document(
    const Key& key,
    const std::string& id,
    const std::string& plaintext
) {
    EncryptedDocument doc;
    doc.id = id;

    if (RAND_bytes(doc.nonce.data(),
                   static_cast<int>(doc.nonce.size())) != 1) {
        throw std::runtime_error("Nonce generation failed");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Could not create encryption context");
    }

    try {
        int length = 0;
        int total = 0;

        doc.ciphertext.resize(plaintext.size() + 16);

        if (EVP_EncryptInit_ex(
                ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_GCM_SET_IVLEN,
                static_cast<int>(doc.nonce.size()), nullptr) != 1 ||
            EVP_EncryptInit_ex(
                ctx, nullptr, nullptr, key.data(),
                doc.nonce.data()) != 1) {
            throw std::runtime_error("Encryption initialization failed");
        }

        // Bind the document identifier as authenticated metadata.
        if (EVP_EncryptUpdate(
                ctx, nullptr, &length,
                reinterpret_cast<const unsigned char*>(id.data()),
                static_cast<int>(id.size())) != 1) {
            throw std::runtime_error("Document authentication failed");
        }

        if (!plaintext.empty() &&
            EVP_EncryptUpdate(
                ctx, doc.ciphertext.data(), &length,
                reinterpret_cast<const unsigned char*>(plaintext.data()),
                static_cast<int>(plaintext.size())) != 1) {
            throw std::runtime_error("Document encryption failed");
        }

        total = length;

        if (EVP_EncryptFinal_ex(
                ctx, doc.ciphertext.data() + total, &length) != 1) {
            throw std::runtime_error("Encryption finalization failed");
        }

        total += length;
        doc.ciphertext.resize(static_cast<std::size_t>(total));

        if (EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_GCM_GET_TAG,
                static_cast<int>(doc.tag.size()), doc.tag.data()) != 1) {
            throw std::runtime_error("Could not obtain authentication tag");
        }
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }

    EVP_CIPHER_CTX_free(ctx);
    return doc;
}

std::string decrypt_document(const Key& key, const EncryptedDocument& doc) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Could not create decryption context");
    }

    std::vector<unsigned char> plaintext(doc.ciphertext.size() + 16);

    try {
        int length = 0;
        int total = 0;

        if (EVP_DecryptInit_ex(
                ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_GCM_SET_IVLEN,
                static_cast<int>(doc.nonce.size()), nullptr) != 1 ||
            EVP_DecryptInit_ex(
                ctx, nullptr, nullptr, key.data(),
                doc.nonce.data()) != 1) {
            throw std::runtime_error("Decryption initialization failed");
        }

        if (EVP_DecryptUpdate(
                ctx, nullptr, &length,
                reinterpret_cast<const unsigned char*>(doc.id.data()),
                static_cast<int>(doc.id.size())) != 1) {
            throw std::runtime_error("Document authentication failed");
        }

        if (!doc.ciphertext.empty() &&
            EVP_DecryptUpdate(
                ctx, plaintext.data(), &length,
                doc.ciphertext.data(),
                static_cast<int>(doc.ciphertext.size())) != 1) {
            throw std::runtime_error("Decryption failed");
        }

        total = length;

        if (EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_GCM_SET_TAG,
                static_cast<int>(doc.tag.size()),
                const_cast<unsigned char*>(doc.tag.data())) != 1) {
            throw std::runtime_error("Could not set authentication tag");
        }

        if (EVP_DecryptFinal_ex(
                ctx, plaintext.data() + total, &length) != 1) {
            throw std::runtime_error(
                "Authentication failed: data may have been modified");
        }

        total += length;
        plaintext.resize(static_cast<std::size_t>(total));
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }

    EVP_CIPHER_CTX_free(ctx);

    return std::string(plaintext.begin(), plaintext.end());
}

class CloudServer {
public:
    void upload(
        const EncryptedDocument& document,
        const std::vector<Token>& tokens
    ) {
        documents_[document.id] = document;

        for (const auto& token : tokens) {
            const std::string token_key =
                to_hex(token.data(), token.size());

            auto& ids = index_[token_key];

            if (std::find(ids.begin(), ids.end(), document.id) == ids.end()) {
                ids.push_back(document.id);
            }
        }

        std::cout << "[Cloud] Stored encrypted document: "
                  << document.id << '\n';
    }

    std::vector<EncryptedDocument> search(const Token& token) const {
        const std::string token_key =
            to_hex(token.data(), token.size());

        std::cout << "[Cloud] Received opaque search token: "
                  << token_key.substr(0, 16) << "...\n";

        std::vector<EncryptedDocument> results;
        const auto it = index_.find(token_key);

        if (it == index_.end()) {
            return results;
        }

        for (const auto& id : it->second) {
            const auto doc_it = documents_.find(id);

            if (doc_it != documents_.end()) {
                results.push_back(doc_it->second);
            }
        }

        return results;
    }

private:
    std::unordered_map<std::string, EncryptedDocument> documents_;
    std::unordered_map<std::string, std::vector<std::string>> index_;
};

class Client {
public:
    Client(const Key& encryption_key,
           const Key& search_key,
           CloudServer& cloud)
        : encryption_key_(encryption_key),
          search_key_(search_key),
          cloud_(cloud) {}

    void add_document(const std::string& id, const std::string& plaintext) {
        std::unordered_set<std::string> unique_words;
        for (const auto& word : tokenize(plaintext)) {
            unique_words.insert(word);
        }

        std::vector<Token> tokens;
        for (const auto& word : unique_words) {
            tokens.push_back(make_token(search_key_, word));
        }

        const auto encrypted =
            encrypt_document(encryption_key_, id, plaintext);

        std::cout << "[Client] Encrypting document " << id << '\n';
        std::cout << "[Client] Sending encrypted document and "
                  << tokens.size() << " keyword tokens to cloud\n";

        cloud_.upload(encrypted, tokens);
    }

    void search(const std::string& word) const {
        const auto words = tokenize(word);

        if (words.size() != 1 || words.front() != word) {
            std::cout << "Enter exactly one keyword using letters or digits.\n";
            return;
        }

        const Token token = make_token(search_key_, words.front());

        std::cout << "\n[Client] User searched for: "
                  << words.front() << '\n';
        std::cout << "[Client] Generated a keyed search token\n";
        std::cout << "[Client -> Cloud] Sending search request\n";

        const auto encrypted_results = cloud_.search(token);

        std::cout << "[Cloud -> Client] Returned "
                  << encrypted_results.size()
                  << " encrypted document(s)\n";

        if (encrypted_results.empty()) {
            std::cout << "No matching documents found.\n";
            return;
        }

        std::cout << "\n[Client] Decrypting results...\n";

        for (const auto& doc : encrypted_results) {
            const auto plaintext =
                decrypt_document(encryption_key_, doc);

            std::cout << "\nDocument: " << doc.id << '\n';
            std::cout << "Content: " << plaintext << '\n';
        }
    }

private:
    Key encryption_key_;
    Key search_key_;
    CloudServer& cloud_;
};

int main() {
    try {
        Key encryption_key{};
        Key search_key{};

        if (RAND_bytes(encryption_key.data(),
                       static_cast<int>(encryption_key.size())) != 1 ||
            RAND_bytes(search_key.data(),
                       static_cast<int>(search_key.size())) != 1) {
            throw std::runtime_error("Key generation failed");
        }

        CloudServer cloud;
        Client client(encryption_key, search_key, cloud);

        std::cout << "=== Keyword Search Demo (Baseline) ===\n\n";

        client.add_document(
            "doc-001",
            "Machine learning helps analyze data.");
        client.add_document(
            "doc-002",
            "Cloud storage protects confidential documents.");
        client.add_document(
            "doc-003",
            "Machine learning can improve cloud security.");

        std::string query;
        std::cout << "\nEnter one keyword to search: ";

        if (!std::getline(std::cin, query)) {
            throw std::runtime_error("Could not read search input");
        }

        client.search(query);

        std::cout << "\nDemo completed.\n";
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
