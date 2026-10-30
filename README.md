# Secure Search over Encrypted Cloud Data: An Implementation and Performance Study

**Research Project | C++ | Cryptography | Blind Storage | Searchable Encryption**

## Overview

This project focuses on implementing and evaluating secure storage and searchable encryption techniques for cloud environments, based on the research paper:

**"Dynamic Searchable Encryption via Blind Storage"**  
Authors: Naveed, Prabhakaran, and Gunter.

The primary objective is to enable users to store encrypted files in an untrusted cloud storage environment and eventually search encrypted documents using keywords without revealing sensitive information to the cloud server.

The project explores two major components:

- **SCATTERSTORE:** A blind storage mechanism that distributes encrypted file blocks across candidate storage locations.
- **BSTORE-SSE:** A searchable symmetric encryption mechanism that enables keyword-based searching over encrypted documents.

## Project Objectives

- Implement cryptographic primitives for secure data handling.
- Develop a blind storage mechanism using pseudorandom candidate block generation.
- Support encrypted file storage, retrieval, updating, and deletion.
- Explore searchable symmetric encryption for encrypted documents.
- Integrate keyword searching with the blind storage layer.
- Evaluate performance, storage overhead, and search efficiency.
- Experiment with a real-world email dataset.

## System Architecture

The intended system consists of the following components:

1. **Client:** Handles cryptographic operations, file processing, and search requests.
2. **Cryptographic Layer:** Provides encryption, hashing, and pseudorandom function operations.
3. **Blind Storage Layer (SCATTERSTORE):** Manages encrypted blocks and candidate storage locations.
4. **Searchable Encryption Layer (BSTORE-SSE):** Manages encrypted keyword indexes and search operations.
5. **Cloud Storage:** Stores encrypted data blocks without directly accessing their plaintext contents.

### Intended Workflow

```text
             CLIENT
                |
                v
       Cryptographic Layer
                |
                v
       Encrypted Documents
                |
                v
       SCATTERSTORE Layer
                |
                v
       Blind Cloud Storage
                |
                v
       BSTORE-SSE Search Layer
                |
                v
       Encrypted Keyword Search
                |
                v
       Retrieve Matching Documents
                |
                v
       Client-Side Decryption
```

*Note: This represents the intended integrated architecture. Full SCATTERSTORE and BSTORE-SSE integration is still under development.*

## Technologies Used

| Technology | Purpose |
|---|---|
| C++ | Core implementation |
| C++17 | Language standard |
| OpenSSL | Cryptographic operations |
| AES-256-GCM | Authenticated encryption |
| SHA-256 | Cryptographic hashing |
| AES-based PRF | Pseudorandom function prototype |
| CMake | Build system |
| Git & GitHub | Version control |

## Current Implementation Status

### Implemented

- Cryptographic utility functions.
- SHA-256 hashing.
- AES-based pseudorandom function.
- AES-GCM encryption and decryption.
- Storage block management.
- Candidate block generation prototype.
- Candidate-based file storage.
- File retrieval.
- File update and deletion operations.
- Multiple-file storage and isolation tests.
- Candidate generation performance benchmarks.
- Preliminary searchable-encryption demonstration using HMAC-SHA-256 keyword tokens and AES-256-GCM encrypted documents.

### Work in Progress

- Complete SCATTERSTORE protocol implementation.
- Paper-faithful candidate selection and access procedures.
- BSTORE-SSE keyword index implementation.
- Integration of searchable encryption with blind storage.
- Enron dataset-based experimentation.
- Comprehensive security and performance evaluation.

**Important:** The current keyword-search demonstration is a separate educational baseline. It is not yet the complete BSTORE-SSE protocol and is not integrated with SCATTERSTORE.

## Project Structure

```text
BlindStorageProject/
│
├── CMakeLists.txt
├── README.md
│
├── include/
│   ├── crypto/
│   │   ├── aes_gcm.h
│   │   ├── aes_prf.h
│   │   ├── crypto_utils.h
│   │   └── hash_utils.h
│   │
│   └── storage/
│       ├── block_crypto.h
│       ├── block_store.h
│       ├── candidate_generator.h
│       ├── file_manager.h
│       └── storage_block.h
│
├── src/
│   ├── crypto/
│   ├── storage/
│   ├── main.cpp
│   ├── block_store_test.cpp
│   ├── candidate_generator_test.cpp
│   ├── candidate_generator_benchmark.cpp
│   ├── file_manager_candidates_test.cpp
│   ├── file_operations_test.cpp
│   ├── multiple_files_test.cpp
│   └── keyword_search_demo.cpp
│
└── backup-before-scatterstore/
```

## Getting Started

### Prerequisites

- Windows, Linux, or a compatible development environment.
- C++17-compatible compiler.
- CMake.
- OpenSSL development libraries.
- Git.

### Clone the Repository

```bash
git clone https://github.com/manasasaragalla/SRE_BLIND-STORAGE.git
```

Navigate into the project:

```bash
cd SRE_BLIND-STORAGE
```

### Build the Project

Configure the project:

```bash
cmake -S . -B build
```

Build:

```bash
cmake --build build
```

Run the main executable:

```bash
./build/blind_storage
```

*Executable names and build targets may vary depending on the CMake configuration and operating system.*

## Testing and Evaluation

The project includes tests and preliminary benchmarks for:

- Candidate generation.
- Candidate uniqueness and index bounds.
- Storage block allocation.
- File storage and retrieval.
- Multiple-file isolation.
- File updates and deletion.
- Candidate generation performance under different storage capacities.

Further evaluation will focus on:

- Search latency.
- Storage overhead.
- Communication overhead.
- Encryption and decryption time.
- Scalability with increasing dataset size.
- Search correctness.

## Dataset

The **Enron Email Dataset** is planned for experimentation with searchable encryption.

It will be used to evaluate keyword-based document retrieval over encrypted email collections and to study system performance under a larger dataset.

## Research Reference

Naveed, M., Prabhakaran, M., and Gunter, C. A.

**Dynamic Searchable Encryption via Blind Storage.**

This research paper serves as the primary reference for the project's SCATTERSTORE and BSTORE-SSE implementation goals.

## Future Enhancements

- Complete implementation of the SCATTERSTORE protocol.
- Implement BSTORE-SSE keyword indexing and searching.
- Integrate encrypted keyword search with blind storage.
- Perform experiments using the Enron dataset.
- Compare performance across different storage capacities.
- Evaluate security properties and protocol overhead.
- Document deviations from the reference research paper.

## Project Status

**Currently under active development.**

This repository contains the ongoing implementation, testing, and performance evaluation of blind storage and searchable encryption techniques.

## Author


**MANASA SARAGALLA**  
**SASIREKHA SADANALA**  
**SUDHARSHANA SURYANARAYANAN**

B.Tech – Data Science and Artificial Intelligence  
Indian Institute of Information Technology (IIIT) Dharwad

B.Tech – Data Science and Artificial Intelligence  
IIIT Dharwad

GitHub: https://github.com/manasasaragalla

---

*This project is developed for academic and research purposes.*