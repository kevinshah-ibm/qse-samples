# Cryptographic Vulnerability Test Files

This directory contains intentionally vulnerable code samples for testing **IBM Quantum Safe Explorer**. These files demonstrate various cryptographic vulnerabilities across multiple programming languages and frameworks.

## ⚠️ WARNING

**DO NOT USE THIS CODE IN PRODUCTION!**

All code in this directory is intentionally insecure and designed solely for testing cryptographic vulnerability detection tools. Using any of these patterns in production systems will create serious security vulnerabilities.

## 📁 Directory Structure

```
sample_files/
├── cpp_files/           # C/C++ vulnerability samples
├── csharp_files/        # C# (.NET) vulnerability samples
├── golang_files/        # Go vulnerability samples
├── java_files/          # Java vulnerability samples
└── python_files/        # Python vulnerability samples
```

## 🔍 Purpose

These files are designed to test IBM Quantum Safe Explorer's ability to detect:

1. **Quantum-vulnerable cryptographic algorithms** (RSA, DSA, ECDSA, DH)
2. **Weak cryptographic algorithms** (MD5, SHA-1, DES, 3DES, RC4)
3. **Insecure implementation patterns** (ECB mode, hardcoded keys, weak random)
4. **Web application security issues** (JWT, sessions, cookies, API keys)
5. **Framework-specific vulnerabilities** (Spring Boot, J2EE, ASP.NET, Django/Flask)

## 📋 Language Coverage

### 1. Python (`python_files/`)

| File | Description | Vulnerabilities |
|------|-------------|-----------------|
| `vulnerable_crypto.py` | Core cryptographic vulnerabilities | MD5, SHA-1, DES, 3DES, RC4, AES-ECB, RSA, DSA, ECDSA, weak random, hardcoded secrets |
| `web_crypto_vulnerabilities.py` | Web framework vulnerabilities | Django/Flask patterns, JWT, sessions, API keys, password hashing, 2FA, OAuth |

**Frameworks Covered:** Django, Flask, PyJWT, PyCryptodome

### 2. Golang (`golang_files/`)

| File | Description | Vulnerabilities |
|------|-------------|-----------------|
| `vulnerable_crypto.go` | Core cryptographic vulnerabilities | MD5, SHA-1, DES, 3DES, RC4, AES-ECB, RSA, DSA, ECDSA, weak random, hardcoded secrets |
| `web_crypto_vulnerabilities.go` | Web service vulnerabilities | JWT, sessions, API keys, password hashing, 2FA, OAuth, cookies, rate limiting |

**Frameworks Covered:** Standard library crypto packages

### 3. C# (.NET) (`csharp_files/`)

| File | Description | Vulnerabilities |
|------|-------------|-----------------|
| `VulnerableCrypto.cs` | Core .NET cryptographic vulnerabilities | MD5, SHA-1, DES, 3DES, RC2, AES-ECB, RSA, DSA, ECDSA, weak random, HMAC |
| `WebCryptoVulnerabilities.cs` | ASP.NET web vulnerabilities | JWT, sessions, API keys, password hashing, 2FA, OAuth, cookies, ViewState |

**Frameworks Covered:** .NET Framework, ASP.NET, System.Security.Cryptography

### 4. Java (`java_files/`)

| File | Description | Vulnerabilities |
|------|-------------|-----------------|
| `VulnerableCryptoExample.java` | Core Java vulnerabilities | MD5, SHA-1, DES, 3DES, AES-128, RSA, DSA, ECDSA, DH, RC4, Blowfish |
| `WeakCryptoVulnerabilities.java` | Comprehensive weak crypto patterns | Weak algorithms, insufficient keys, deprecated primitives, unsafe random |
| `SpringBootCryptoVulnerabilities.java` | Spring Boot specific vulnerabilities | Spring Security, JWT, sessions, REST APIs, OAuth2, 2FA, file encryption |
| `J2EECryptoVulnerabilities.java` | J2EE/Jakarta EE vulnerabilities | Servlets, EJB, JPA, JAAS, JSF, JAX-RS, JMS, JNDI |

**Frameworks Covered:** Spring Boot, Spring Security, J2EE/Jakarta EE, JJWT

### 5. C/C++ (`cpp_files/`)

| File | Description | Vulnerabilities |
|------|-------------|-----------------|
| `vulnerable_crypto.cpp` | Basic C++ vulnerabilities | MD5, AES-ECB, hardcoded keys, weak random, buffer issues |
| `openssl_vulnerabilities.cpp` | Comprehensive OpenSSL vulnerabilities | MD5, SHA-1, DES, 3DES, RC4, AES-ECB, RSA, DSA, ECDSA, weak random, certificates |

**Libraries Covered:** OpenSSL

## 🎯 Vulnerability Categories

### Quantum-Vulnerable Algorithms
- **RSA** (512-bit, 1024-bit, 2048-bit)
- **DSA** (1024-bit)
- **ECDSA** (P-256, P-384)
- **Diffie-Hellman** (DH)
- **Elliptic Curve Cryptography** (ECC)

### Weak Hash Algorithms
- **MD5** - Broken, collision attacks
- **SHA-1** - Deprecated, collision attacks demonstrated
- **MD4** - Severely broken

### Weak Symmetric Encryption
- **DES** - 56-bit key, easily brute-forced
- **3DES/Triple DES** - Quantum vulnerable, deprecated
- **RC4** - Biased, multiple attacks
- **RC2** - Weak block cipher
- **Blowfish** - With weak keys

### Insecure Implementation Patterns
- **ECB Mode** - Electronic Codebook, pattern leakage
- **Static/Hardcoded IVs** - Initialization Vector reuse
- **Hardcoded Keys** - Embedded secrets in code
- **Weak Random** - Using non-cryptographic RNGs
- **Insufficient Key Lengths** - Below recommended sizes
- **No Padding/Weak Padding** - PKCS1 padding vulnerabilities

### Web Application Vulnerabilities
- **JWT Issues** - Weak secrets, 'none' algorithm, no expiration
- **Session Management** - Weak session IDs, predictable tokens
- **API Keys** - Weak generation, predictable patterns
- **Password Hashing** - MD5/SHA-1 for passwords, no salt
- **2FA Weaknesses** - Weak TOTP secrets, predictable backup codes
- **OAuth/OpenID** - Weak state parameters, predictable secrets
- **Cookie Security** - No Secure flag, weak encryption
- **Timing Attacks** - Non-constant-time comparisons

## 🚀 Usage with IBM Quantum Safe Explorer

### Running Scans

1. **Install IBM Quantum Safe Explorer** following the official documentation
2. **Navigate to the sample_files directory**
3. **Run scans on specific language folders:**

```bash
# Scan Python files
qse scan python_files/

# Scan Java files
qse scan java_files/

# Scan all files
qse scan .
```

### Expected Results

IBM Quantum Safe Explorer should detect:
- ✓ Quantum-vulnerable algorithms (RSA, DSA, ECDSA, DH)
- ✓ Weak hash functions (MD5, SHA-1)
- ✓ Deprecated encryption algorithms (DES, 3DES, RC4)
- ✓ Insecure modes of operation (ECB)
- ✓ Hardcoded cryptographic secrets
- ✓ Weak random number generation
- ✓ Insufficient key lengths
- ✓ Framework-specific vulnerabilities

## 📚 References

### IBM Quantum Safe Resources
- [IBM Quantum Safe Cryptography Course](https://quantum.cloud.ibm.com/learning/en/courses/quantum-safe-cryptography)
- [IBM Quantum Safe Explorer Documentation](https://www.ibm.com/docs/en/quantum-safe/quantum-safe-explorer/2.x)

### Cryptographic Standards
- **NIST Post-Quantum Cryptography** - [csrc.nist.gov/projects/post-quantum-cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- **OWASP Cryptographic Storage Cheat Sheet** - [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

## 🔐 Secure Alternatives

For production code, use:

### Quantum-Safe Algorithms
- **CRYSTALS-Kyber** - Key encapsulation
- **CRYSTALS-Dilithium** - Digital signatures
- **SPHINCS+** - Stateless hash-based signatures
- **FALCON** - Lattice-based signatures

### Secure Hash Functions
- **SHA-256** or **SHA-3** (minimum)
- **SHA-512** (recommended)
- **BLAKE2** or **BLAKE3**

### Secure Symmetric Encryption
- **AES-256-GCM** - Authenticated encryption
- **ChaCha20-Poly1305** - Modern stream cipher with authentication
- **AES-256-CBC** with HMAC - If GCM not available

### Secure Random Number Generation
- **crypto/rand** (Go)
- **secrets** module (Python)
- **SecureRandom** (Java)
- **RNGCryptoServiceProvider** (C#)
- **RAND_bytes** (OpenSSL)

### Password Hashing
- **Argon2id** (recommended)
- **bcrypt** (good alternative)
- **scrypt** (acceptable)
- **PBKDF2** with SHA-256/SHA-512 (minimum)

## 📝 Notes

- All files include comments marking specific vulnerabilities
- Each file has a main/demo function showing usage
- Files are self-contained and can be tested independently
- Some files may require external dependencies (noted in comments)
- Import errors in IDE are expected (libraries not installed)

## 🤝 Contributing

These files are for testing purposes. If you identify additional vulnerability patterns that should be included, please document them following the existing format.

## 📄 License

These test files are provided for educational and testing purposes only.

---

**Created with Bob** - AI-powered code assistant
**Last Updated:** 2026-02-23