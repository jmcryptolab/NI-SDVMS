# NI-SDVMS: Non-Interactive Strong Designated Verifier Multi-Signature Scheme

NI-SDVMS is a **lattice-based non-interactive strong designated-verifier multi-signature scheme**, designed for blockchain authentication and high-security applications.  
This implementation integrates:

- **Dilithium signatures** (FIPS 204)
- **Kyber KEM** (FIPS 203)
- **MLWE / MSIS hardness assumptions**
- **XOF-based deterministic randomness**

The repository provides a working C/C++ implementation including key generation, signing, aggregation, KEM-based hash protection, designated-verifier decryption, and correctness verification.

---

## 🚀 Features

- **Non-interactive multi-signature**
- **Strong designated-verifier validation**
- **Post-quantum security (MLWE / MSIS)**
- **Deterministic seed generation**
- **Blockchain-friendly implementation**

---

## 📂 Project Structure

```
NI-SDVMS/
│
├── src/                  # Main implementation
│   ├── main.c
│   ├── d_sign.c
│   ├── d_sign.h
│   ├── d_randombytes.c
│   ├── d_randombytes.h
│   ├── k_kem.c
│   ├── k_kem.h
│
├── tests/                # Kyber/Dilithium experimental programs
│   ├── k-d-fixed-final.cpp
│   ├── k-d-no-openssl.cpp
│   └── k-d-timed-fixed.cpp
│
├── Makefile              # One-command build (recommended)
├── LICENSE
└── README.md
```

---

## 🛠 Build Instructions

### Linux / MacOS

```bash
make
./ni_sdvms
```

### Windows (MinGW)

```bash
make
ni_sdvms.exe
```

Requirements:

- GCC / Clang / MSVC
- OpenSSL (`libssl` + `libcrypto`)

---

## 🔐 Security Guarantees

NI-SDVMS security relies on:

- **Module-LWE** (public-key hardness)
- **Module-SIS** (signature unforgeability)
- **Discrete Gaussian sampling**
- **Hash-based Fiat–Shamir transformation**
- **IND-CCA secure KEM protection**

This combination provides strong post-quantum security.

---

## 📜 License

This project is released under the **MIT License**, permitting academic and commercial use.

---

## ✨ Citation

If this repository is used in academic work, please cite:

```
jm Zhang, zh Liu, dd Y： A Lattice-Based Non-Interactive Strong Designated-Verifier Multi-Signature Scheme for Ethereum" GitHub, 2025.
https://github.com/jmcryptolab/NI-SDVMS
```
