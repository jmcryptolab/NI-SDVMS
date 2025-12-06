# NI-SDVMS: Non-Interactive Strong Designated Verifier Multi-Signature Scheme

NI-SDVMS is a **lattice-based non-interactive strong designated-verifier multi-signature scheme**, designed for blockchain authentication and high-security applications.  
The scheme integrates:

- **Dilithium** (FIPS 204) — lattice-based digital signature  
- **Kyber KEM** (FIPS 203) — post-quantum encryption  
- **MLWE/MSIS hardness assumptions**  
- **XOF-based deterministic seed generation**  

This project provides a working C/C++ implementation of NI-SDVMS with key generation, signing, aggregation, designated-verifier decryption, and correctness verification.

---

## 🚀 Features

- **Non-interactive** multi-signature (signers do not communicate)
- **Strong designated verifier** (only the designated party can validate)
- **Post-quantum security** (MLWE / MSIS)
- **Deterministic seed generation**
- **KEM-protected hash aggregation**
- **Compatible with blockchain smart contract verification**
- **Lightweight implementation in portable C/C++**

---

## 📂 Project Structure

