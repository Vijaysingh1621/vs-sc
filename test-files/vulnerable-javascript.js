// Test file with various JavaScript vulnerabilities for the scanner

// OWASP A01: Broken Access Control
const isAdmin = true; // Hardcoded admin access
function checkAccess(user) {
    if (user || true) { // Access control bypass
        return "Access granted";
    }
}

// OWASP A02: Cryptographic Failures
const crypto = require('crypto');
const password = "admin123"; // Hardcoded password
const secret = "my-secret-key"; // Hardcoded secret
const hash = crypto.createHash('md5').update(password).digest('hex'); // Weak MD5 hashing

// OWASP A03: Injection
const mysql = require('mysql');
function getUserData(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId; // SQL Injection
    return mysql.query(query);
}

function executeCommand(userInput) {
    eval(userInput); // Code injection vulnerability
}

// OWASP A04: Insecure Design
setTimeout("alert('XSS')", 1000); // String-based setTimeout
const dynamicFunction = new Function("return " + userInput); // Dynamic function creation

// OWASP A05: Security Misconfiguration
const debug = true; // Debug mode enabled
const cors = {
    origin: "*", // Unrestricted CORS
    credentials: true
};

// OWASP A06: Vulnerable Components
const jquery = require('jquery@1.8.0'); // Outdated jQuery version
const react = require('react@15.6.0'); // Outdated React version

// OWASP A07: Authentication Failures
function login(username, password) {
    if (password == "password123") { // Weak password comparison
        return { success: true };
    }
}

// OWASP A08: Software Integrity Failures
document.write('<script src="http://cdn.example.com/script.js"></script>'); // HTTP resource

// OWASP A09: Logging Failures
console.log("User password: " + userPassword); // Logging sensitive data
console.log("API token: " + apiToken); // Logging tokens

// OWASP A10: SSRF
const axios = require('axios');
function fetchData(url) {
    return axios.get(req.query.url); // Server-side request forgery
}

// SANS CWE-79: Cross-site Scripting
function displayMessage(message) {
    document.getElementById('output').innerHTML = message; // XSS vulnerability
    document.write(userInput); // Direct DOM manipulation
}

// SANS CWE-89: SQL Injection (additional examples)
const query2 = `SELECT * FROM products WHERE name = '${productName}'`; // Template literal injection

// SANS CWE-352: CSRF
function updateProfile(data) {
    // Missing CSRF token validation
    fetch('/api/profile', {
        method: 'POST',
        body: JSON.stringify(data)
    });
}

// SANS CWE-798: Hard-coded Credentials
const apiKey = "sk-1234567890abcdef"; // Hardcoded API key
const dbPassword = "root123"; // Hardcoded database password

// SANS CWE-22: Path Traversal
const fs = require('fs');
function readFile(filename) {
    return fs.readFileSync(filename); // No path validation - allows ../../../etc/passwd
}

// SANS CWE-94: Code Injection
function processTemplate(template, data) {
    return eval(`\`${template}\``); // Template injection
}

// SANS CWE-502: Deserialization
function deserializeData(serializedData) {
    return JSON.parse(serializedData); // Unsafe deserialization without validation
}

// SANS CWE-327: Weak Cryptography
const weakHash = crypto.createHash('sha1').update(data).digest('hex'); // SHA-1 is weak
const base64Encoded = Buffer.from(sensitiveData).toString('base64'); // Base64 is not encryption

// SANS CWE-209: Information Exposure
process.on('uncaughtException', (err) => {
    console.log(err.stack); // Exposing stack traces
});

// SANS CWE-476: NULL Pointer Dereference
function processUser(user) {
    return user.name.toUpperCase(); // No null check
}

// Additional vulnerabilities
const userAgent = req.headers['user-agent'];
exec(`ping ${userAgent}`); // Command injection through user agent