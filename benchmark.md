# Benchmarks
## Runtime Environment

- **OS**: macOS  
- **Architecture**: `intel64`  
- **CPU**: Intel Core i9-9880H @ 4.5 GHz  
- **Participants**: `5`  
- **Threshold**: `3`  

**SHA**: A cryptographic hash function, specifically **truncated SHA-512 (256-bit)**

**Poseidon**: A hash function designed for **ZK-friendly operations**. In the same context of generating the **SSID** (as a replacement for SHA).

---

## ECDSA (secp256k1)

| Operation                      | Runtime/iteration | Iterations | Total Time   |
|--------------------------------|-------------------|------------|-------------:|
| **Key Generation**             | 4.35s            | 10         | 43.50s       |
| **Resharing**                  | 4.10s            | 10         | 40.51s       |
| **ECDSA Verification (SHA)**   | 0.36s            | 10         | 3.62s        |
| **ECDSA Verification (Poseidon)** | 3.852ms        | 10         | 38.52ms      |

---

## EdDSA (ed25519)

| Operation                      | Runtime/iteration | Iterations | Total Time   | Notes                                      |
|--------------------------------|-------------------|------------|-------------:|--------------------------------------------|
| **Key Generation**             | 597ms            | 10         | 6.695s       | Single iteration without loop: `1.288s`    |
| **Resharing**                  | 678ms            | 10         | 6.815s       | ——                                         |
| **EDDSA Verification (SHA)**   | 91ms             | 10         | 1.517s       | ——                                         |
| **EDDSA Verification (Poseidon)** | —             | 10         | —            | Not yet measured                           |

---

## EdDSA (Baby Jubjub)

| Operation                      | Runtime/iteration | Iterations | Total Time   | Notes                                      |
|--------------------------------|-------------------|------------|-------------:|--------------------------------------------|
| **Key Generation**             | 18.9226ms                 | —          | 189.226ms            | TBD                                        |
| **Resharing**                  | —                 | —          | —            | TBD                                        |
| **Verification (Poseidon)**    | 1.143372ms                 | —          | 11.43372ms            | TBD                                        |

---
