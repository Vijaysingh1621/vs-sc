# Vulnerability Test Files

This directory contains sample files with intentional security vulnerabilities to test the Vulnerability Scanner Pro extension.

## Test Files

### 1. vulnerable-javascript.js
Contains JavaScript vulnerabilities including:
- **OWASP Top 10**: Broken access control, cryptographic failures, injection flaws, insecure design, security misconfigurations, vulnerable components, authentication failures, software integrity failures, logging failures, SSRF
- **SANS Top 25**: SQL injection, XSS, command injection, path traversal, code injection, hardcoded credentials, CSRF, deserialization, weak cryptography, information exposure

### 2. vulnerable-java.java  
Contains Java vulnerabilities including:
- **OWASP Top 10**: All major categories with Java-specific implementations
- **SANS Top 25**: Buffer overflow simulation, SQL injection, command injection, authentication bypasses, file upload vulnerabilities, authorization flaws, integer overflow, null pointer dereference

### 3. vulnerable-python.py
Contains Python vulnerabilities including:
- **OWASP Top 10**: Complete coverage with Python/Flask examples
- **SANS Top 25**: Code injection via eval/exec, unsafe deserialization with pickle, YAML loading vulnerabilities, SSRF, XXE, race conditions, memory disclosure

## How to Test

1. Open any of these files in VS Code with the Vulnerability Scanner Pro extension installed
2. The extension will automatically scan the files and detect vulnerabilities
3. Check the Problems panel for diagnostic markers
4. Open the Security panel in the sidebar to see detailed vulnerability reports
5. Use the "🔧 Auto Fix" buttons to automatically remediate fixable vulnerabilities

## Expected Detections

Each file should trigger multiple vulnerability detections across different severity levels:
- **Critical**: SQL injection, command injection, code injection
- **High**: XSS, SSRF, authentication bypasses, hardcoded credentials  
- **Medium**: Weak cryptography, CSRF, information exposure
- **Low**: Debug mode enabled, logging sensitive data

## Security Note

⚠️ **WARNING**: These files contain intentional security vulnerabilities and should NEVER be used in production code. They are for testing purposes only.