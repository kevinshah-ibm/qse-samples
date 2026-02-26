# IBM Quantum Safe Explorer: API Discovery vs Cryptography Analysis

A comprehensive comparison of the two scan types available in IBM Quantum Safe Explorer.

---

## Overview

IBM Quantum Safe Explorer provides two distinct scan types for analyzing Java applications:

1. **API Discovery Scan** - Identifies where cryptographic APIs are used
2. **Cryptography Analysis Scan** - Analyzes security of cryptographic implementations

---

## Supported Languages

Both scan types currently support the same language:

| Scan Type | Supported Languages |
|-----------|-------------------|
| **API Discovery** | Java |
| **Cryptography Analysis** | Java |

### UI Behavior

- When both scans are available for a language (Java), a **toggle appears** to switch between scan results
- If only one scan is available, the toggle is **disabled**

---

## Scan Comparison

### Quick Reference Table

| Feature | Cryptography Analysis Scan | API Discovery Scan |
|---------|---------------------------|-------------------|
| **Purpose** | Security analysis of cryptographic implementations | Identify cryptographic API usage |
| **Results Include** | Properties, vulnerabilities, function parameter trace | API usage list, metadata |
| **Finds Vulnerabilities?** | ✅ Yes | ❌ No |
| **Shows Call Traces?** | ✅ Yes, detailed | ❌ No |
| **Highlights Weak Crypto?** | ✅ Yes | ❌ No |
| **Focus** | Algorithm strength, misconfiguration, unsafe patterns | Where APIs are called in the code |
| **Toggles with Other Scan?** | ✅ Yes (for Java) | ✅ Yes (for Java) |

---

## Cryptography Analysis Scan

### Purpose

To surface cryptographic weaknesses, misconfigurations, and risks in cryptographic implementations.

### What It Analyzes

The Cryptography Analysis scan focuses on detecting and analyzing:
- Cryptographic usage patterns
- Security weaknesses in implementations
- Algorithm and parameter compliance
- Post-quantum readiness

### Scan Results Structure

When reviewing a Cryptography Analysis scan for a Java project, selecting an asset shows **three key sections**:

#### 1. Properties

Provides metadata about the cryptographic asset:

- **Cryptographic algorithm used** (e.g., RSA, AES, SHA-256)
- **Library or provider** (e.g., OpenSSL, JCA, Bouncy Castle)
- **Key lengths** (public/private key sizes)
- **Algorithm parameters**

**Purpose**: Assess whether the algorithm and parameters meet security and post-quantum standards.

#### 2. Vulnerabilities

Lists all detected cryptographic vulnerabilities:

- ❌ Weak algorithms (e.g., MD5, SHA-1, DES)
- ❌ Insufficient key lengths (e.g., RSA-1024)
- ❌ Deprecated or insecure cryptographic primitives
- ❌ Unsafe random number generation
- ❌ Hardcoded keys or initialization vectors

**Each vulnerability includes**:
- Relevant file path and line number
- Expandable view showing multiple occurrences
- Reference markers (clickable) to navigate to the code
- Severity level and remediation guidance

#### 3. Function Parameter Trace

Shows a detailed **call-stack-based trace** of how parameters flow into cryptographic functions.

**Helps analysts**:
- Identify root causes of vulnerabilities
- Understand data flow through the application
- Track insecure parameter origins
- Follow parameter propagation through objects and functions

**Features**:
- Recursive expansion through objects and functions
- Complete call chain visualization
- Parameter value tracking
- Source-to-sink analysis

### Example Use Cases

1. **Identifying weak algorithms**: Find all uses of MD5 or SHA-1
2. **Key length validation**: Ensure RSA keys are at least 2048 bits
3. **Post-quantum readiness**: Identify algorithms vulnerable to quantum attacks
4. **Compliance checking**: Verify adherence to security standards (FIPS, NIST)
5. **Migration planning**: Assess scope of cryptographic updates needed

---

## API Discovery Scan

### Purpose

To surface API-level information about cryptographic library usage and identify potential entry points for deeper analysis.

### What It Analyzes

The API Discovery scan focuses on:
- **Where** cryptographic APIs are invoked
- **Which** libraries the code interacts with
- **How** cryptographic functions are called
- **Inventory** of cryptographic API usage

### Scan Results Structure

The API Discovery scan provides:

- **List of API usage** related to cryptographic libraries or functions
- **Structured metadata** about discovered API calls
- **Location information** (files, classes, methods)
- **API signatures** and calling patterns

### What It Does NOT Include

- ❌ Vulnerability analysis
- ❌ Parameter or key size analysis
- ❌ Deep call traces
- ❌ Security assessments
- ❌ Compliance checking

### Example Use Cases

1. **API inventory**: Create a complete list of cryptographic APIs in use
2. **Library identification**: Determine which crypto libraries are dependencies
3. **Entry point discovery**: Find where to start deeper security analysis
4. **Code navigation**: Quickly locate cryptographic code sections
5. **Impact assessment**: Understand scope before library updates

---

## Key Differences

### Focus

| Aspect | Cryptography Analysis | API Discovery |
|--------|---------------------|---------------|
| **What** | Security and correctness | Presence and location |
| **Why** | Find vulnerabilities | Map API usage |
| **How** | Deep parameter analysis | Surface-level detection |
| **Output** | Security findings | API inventory |

### Analysis Depth

**Cryptography Analysis**:
- ✅ Deep security analysis
- ✅ Parameter flow tracking
- ✅ Vulnerability detection
- ✅ Compliance validation
- ✅ Risk assessment

**API Discovery**:
- ✅ API presence detection
- ✅ Location mapping
- ✅ Library identification
- ❌ No security analysis
- ❌ No vulnerability detection

### Typical Workflow

```
1. Run API Discovery Scan
   ↓
   Identify where crypto APIs are used
   ↓
2. Run Cryptography Analysis Scan
   ↓
   Analyze security of those implementations
   ↓
3. Review vulnerabilities and traces
   ↓
4. Remediate security issues
```

---

## When to Use Each Scan

### Use API Discovery When:

- 📋 You need an **inventory** of cryptographic API usage
- 🔍 You want to **locate** where crypto code exists
- 📊 You're planning a **migration** and need scope assessment
- 🗺️ You need to **map** dependencies on crypto libraries
- 🚀 You're starting a **new security assessment**

### Use Cryptography Analysis When:

- 🔒 You need to **assess security** of crypto implementations
- 🐛 You want to **find vulnerabilities** in crypto code
- ✅ You need **compliance validation** (FIPS, NIST, PQC)
- 🔬 You want **detailed parameter analysis**
- 🛡️ You're performing a **security audit**
- 🔄 You're planning **post-quantum migration**

---

## Summary

### In One Sentence

> **Cryptography Analysis** tells you **what's insecure and why**, while **API Discovery** tells you **where cryptographic APIs are used**.

### Complementary Nature

These scans are designed to work together:

1. **API Discovery** provides the **map** of cryptographic usage
2. **Cryptography Analysis** provides the **security assessment** of that usage

### Best Practice

For comprehensive cryptographic security assessment:

1. ✅ Run **both scans** on your Java codebase
2. ✅ Use **API Discovery** to understand scope
3. ✅ Use **Cryptography Analysis** to identify risks
4. ✅ Prioritize remediation based on vulnerability severity
5. ✅ Re-scan after fixes to validate improvements

---

## Additional Resources

- [IBM Quantum Safe Explorer Documentation](https://www.ibm.com/quantum-safe)
- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Java Cryptography Architecture (JCA) Guide](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html)

---

**Document Version**: 1.0  
**Last Updated**: February 2026  
**Supported Languages**: Java
