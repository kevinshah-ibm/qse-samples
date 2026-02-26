# Quantum Safe Explorer Pilot

### IBM QSE Installation & Usage Guide

This README provides step‑by‑step instructions for installing and running **IBM Quantum Safe Explorer**, including VS Code extension setup and post‑installation configuration.

***

## 📦 1. Download Required Software

### **1a. Navigate to the Software Downloads Page**

Choose the appropriate download site:

*   **IBMers:**  
    [https://webxlsdf.webui-dswdown.dal.app.cirrus.ibm.com/](https://webxlsdf.webui-dswdown.dal.app.cirrus.ibm.com/)

*   **Clients:**  
    [https://www.ibm.com/software/passportadvantage/pao-customer](https://www.ibm.com/software/passportadvantage/pao-customer)

Be sure to **accept all license and usage agreements**.

***

### **1b. Download the Installer (Optional)**

Download the Quantum Safe Explorer installer package if you prefer installing via PKG.

***

### **1c. Download Platform‑Specific Applications**

Download the application bundles corresponding to your operating system.

***

## 🛠️ 2. Install Quantum Safe Explorer and VS Code Extension

### **2a. Install the macOS Application**

1.  Locate the file:  
    **`IBM Quantum Safe Explorer.pkg`**
2.  Double‑click to run the installer.
3.  Follow on‑screen installation steps.

> **Note:** Administrator privileges may be required.

***

### **2b. Install the VS Code Extension (`.vsix`)**

1.  Locate the file:  
    **`quantum-safe-explorer-1.0.1.vsix`**
2.  Install using the VS Code CLI:

```bash
code --install-extension ibm-quantum-safe-explorer-1.0.1.vsix
```

#### ✔ Enabling the `code` command (if not already installed)

If the `code` CLI is not recognized:

1.  Open **Visual Studio Code**
2.  Open the Command Palette:
    *   **Windows/Linux:** `Ctrl + Shift + P`
    *   **macOS:** `Cmd + Shift + P`
3.  Run:  
    **Shell Command: Install 'code' command in PATH**
4.  Approve the installation (may require admin password)
5.  Retry (may require terminal restart):

```bash
code --install-extension ibm-quantum-safe-explorer-1.0.1.vsix
```

***

## ⚙️ 3. Post‑Installation VS Code Configuration

Refer to the full configuration guide here:

*\[\[https://www.ibm.com/docs/en/quantum-safe/quantum-safe-explorer/2.x_beta?topic=configuring-quantum-safe-explorer-visual-studio-code-extension]]*

This may include setting paths, credentials, workspace settings, or additional tooling.

Select the appropriate version from the top left "Change version" dropdown.

***

## 🔍 4. Run a Quantum Safe Scan Using the VS Code Extension

Once installed and configured:

1.  Open VS Code
2.  Open a project or files to scan
3.  Open the Command Palette:
    -   **Windows/Linux:** `Ctrl + Shift + P`
    -   **macOS:** `Cmd + Shift + P`
4.  Run:  
    - **Quantum Safe Explorer: Scan API Discovery**
    *or*
    - **Quantum Safe Explorer: Scan Cryptography Analysis**

***

## 📸 Screenshots

## Troubleshooting

### Scan Cryptography Analysis command does not show any vulnerabilities or algorithms
- .java files need to be compiled to .class files to actually show up on the analysis. Compile them by running:
```bash
javac your-file.java
```

### Scan results are not updating
- QSE uses `qs_explorer_result` and `qs_scan_result` as its *cache*. Delete these and re-run the command to get a fresh scan.
