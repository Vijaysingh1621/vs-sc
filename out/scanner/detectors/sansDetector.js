"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SansDetector = void 0;
class SansDetector {
    constructor() {
        this.patterns = {
            // CWE-89: SQL Injection
            'sql-injection': [
                /["'].*?\+.*?["'].*?(?:SELECT|INSERT|UPDATE|DELETE)/gi,
                /query\s*\(\s*["'].*?\$.*?["']/gi,
                /execute\s*\(\s*["'].*?\+.*?["']/gi
            ],
            // CWE-78: OS Command Injection
            'command-injection': [
                /exec\s*\(\s*.*?\$_/gi,
                /system\s*\(\s*.*?\$_/gi,
                /shell_exec\s*\(\s*.*?\$_/gi,
                /passthru\s*\(\s*.*?\$_/gi
            ],
            // CWE-79: Cross-site Scripting
            'xss': [
                /innerHTML\s*=\s*.*?\+/gi,
                /document\.write\s*\(\s*.*?\+/gi,
                /\$\(.*?\)\.html\s*\(\s*.*?\+/gi,
                /echo\s*\$_(?:GET|POST|REQUEST)/gi
            ],
            // CWE-120: Buffer Overflow
            'buffer-overflow': [
                /strcpy\s*\(/gi,
                /strcat\s*\(/gi,
                /sprintf\s*\(/gi,
                /gets\s*\(/gi
            ],
            // CWE-352: Cross-Site Request Forgery
            'csrf': [
                /form.*method\s*=\s*["']post["'](?!.*csrf)/gi,
                /\$_POST(?!.*csrf_token)/gi,
                /request\.post\(\s*(?!.*csrf)/gi
            ],
            // CWE-22: Path Traversal
            'path-traversal': [
                /\.\.[\/\\]/gi,
                /include\s*\(\s*\$_/gi,
                /require\s*\(\s*\$_/gi,
                /file_get_contents\s*\(\s*\$_/gi
            ],
            // CWE-434: Unrestricted Upload
            'unrestricted-upload': [
                /move_uploaded_file.*?\$_FILES/gi,
                /\$_FILES.*?(?!.*validation)/gi,
                /upload.*(?!.*validation)/gi
            ],
            // CWE-798: Hard-coded Credentials
            'hardcoded-credentials': [
                /password\s*=\s*["'][^"']{3,}["']/gi,
                /api_key\s*=\s*["'][^"']{10,}["']/gi,
                /secret\s*=\s*["'][^"']{10,}["']/gi,
                /token\s*=\s*["'][^"']{20,}["']/gi
            ],
            // CWE-285: Improper Authorization
            'improper-authorization': [
                /if\s*\(\s*\$_SESSION\s*\)/gi,
                /authorized\s*=\s*true/gi,
                /admin\s*=\s*1/gi
            ],
            // CWE-732: Incorrect Permission Assignment
            'incorrect-permissions': [
                /chmod\s*\(\s*.*?,\s*0777\s*\)/gi,
                /umask\s*\(\s*0\s*\)/gi,
                /file_put_contents.*LOCK_EX/gi
            ],
            // CWE-209: Information Exposure
            'info-exposure': [
                /error_reporting\s*\(\s*E_ALL\s*\)/gi,
                /display_errors\s*=\s*1/gi,
                /phpinfo\s*\(\s*\)/gi,
                /print_r\s*\(\s*\$_/gi
            ],
            // CWE-327: Weak Cryptography
            'weak-crypto': [
                /md5\s*\(/gi,
                /sha1\s*\(/gi,
                /crypt\s*\(/gi,
                /base64_encode\s*\(/gi
            ],
            // CWE-190: Integer Overflow
            'integer-overflow': [
                /int\s*\(\s*\$_GET/gi,
                /intval\s*\(\s*\$_POST/gi,
                /\+\+.*?\$_/gi
            ],
            // CWE-476: NULL Pointer Dereference
            'null-pointer': [
                /\-\>.*?(?!.*null.*check)/gi,
                /\[.*?\](?!.*isset)/gi,
                /\$.*?\-\>.*?(?!.*null)/gi
            ],
            // CWE-94: Code Injection
            'code-injection': [
                /eval\s*\(\s*\$_/gi,
                /assert\s*\(\s*\$_/gi,
                /preg_replace.*?\/e/gi,
                /create_function/gi
            ],
            // CWE-611: XML External Entities
            'xxe': [
                /simplexml_load_string\s*\(\s*\$_/gi,
                /DOMDocument.*loadXML\s*\(\s*\$_/gi,
                /XMLReader.*XML\s*\(\s*\$_/gi
            ],
            // CWE-918: SSRF
            'ssrf': [
                /file_get_contents\s*\(\s*\$_/gi,
                /curl_setopt.*CURLOPT_URL.*\$_/gi,
                /fopen\s*\(\s*\$_/gi
            ],
            // CWE-502: Deserialization
            'deserialization': [
                /unserialize\s*\(\s*\$_/gi,
                /pickle\.loads\s*\(/gi,
                /yaml\.load\s*\(/gi,
                /JSON\.parse\s*\(\s*.*?\$_/gi
            ],
            // CWE-125: Out-of-bounds Read
            'oob-read': [
                /\[\s*\$_.*?\]/gi,
                /substr\s*\(\s*.*?,\s*\$_/gi,
                /array_slice.*?\$_/gi
            ],
            // CWE-20: Improper Input Validation
            'input-validation': [
                /\$_(?:GET|POST|REQUEST|COOKIE)(?!.*filter)/gi,
                /input\s*\(\s*(?!.*validation)/gi,
                /request\.(?:form|args)(?!.*valid)/gi
            ]
        };
    }
    async detect(filePath, content, language) {
        const vulnerabilities = [];
        const lines = content.split('\n');
        for (const [vulnType, patterns] of Object.entries(this.patterns)) {
            for (const pattern of patterns) {
                let match;
                while ((match = pattern.exec(content)) !== null) {
                    const lineNumber = this.getLineNumber(content, match.index);
                    const lineContent = lines[lineNumber - 1];
                    const column = match.index - content.lastIndexOf('\n', match.index) - 1;
                    vulnerabilities.push({
                        id: `sans-${vulnType}-${lineNumber}-${column}`,
                        type: vulnType,
                        category: 'SANS',
                        severity: this.getSeverity(vulnType),
                        title: this.getTitle(vulnType),
                        description: this.getDescription(vulnType),
                        file: filePath,
                        line: lineNumber,
                        column: Math.max(0, column),
                        length: match[0].length,
                        code: lineContent.trim(),
                        cwe: this.getCWE(vulnType),
                        recommendation: this.getRecommendation(vulnType),
                        fixable: this.isFixable(vulnType)
                    });
                }
            }
        }
        return vulnerabilities;
    }
    getLineNumber(content, index) {
        return content.substring(0, index).split('\n').length;
    }
    getSeverity(vulnType) {
        const severityMap = {
            'sql-injection': 'critical',
            'command-injection': 'critical',
            'xss': 'high',
            'buffer-overflow': 'critical',
            'csrf': 'medium',
            'path-traversal': 'high',
            'unrestricted-upload': 'high',
            'hardcoded-credentials': 'high',
            'improper-authorization': 'high',
            'incorrect-permissions': 'medium',
            'info-exposure': 'medium',
            'weak-crypto': 'medium',
            'integer-overflow': 'medium',
            'null-pointer': 'medium',
            'code-injection': 'critical',
            'xxe': 'high',
            'ssrf': 'high',
            'deserialization': 'high',
            'oob-read': 'medium',
            'input-validation': 'high'
        };
        return severityMap[vulnType] || 'medium';
    }
    getTitle(vulnType) {
        const titleMap = {
            'sql-injection': 'SQL Injection',
            'command-injection': 'OS Command Injection',
            'xss': 'Cross-Site Scripting (XSS)',
            'buffer-overflow': 'Buffer Overflow',
            'csrf': 'Cross-Site Request Forgery (CSRF)',
            'path-traversal': 'Path Traversal',
            'unrestricted-upload': 'Unrestricted File Upload',
            'hardcoded-credentials': 'Hard-coded Credentials',
            'improper-authorization': 'Improper Authorization',
            'incorrect-permissions': 'Incorrect Permission Assignment',
            'info-exposure': 'Information Exposure',
            'weak-crypto': 'Weak Cryptography',
            'integer-overflow': 'Integer Overflow',
            'null-pointer': 'NULL Pointer Dereference',
            'code-injection': 'Code Injection',
            'xxe': 'XML External Entity (XXE)',
            'ssrf': 'Server-Side Request Forgery (SSRF)',
            'deserialization': 'Insecure Deserialization',
            'oob-read': 'Out-of-bounds Read',
            'input-validation': 'Improper Input Validation'
        };
        return titleMap[vulnType] || 'Security Vulnerability';
    }
    getDescription(vulnType) {
        const descMap = {
            'sql-injection': 'SQL injection vulnerability allows attackers to execute arbitrary SQL commands.',
            'command-injection': 'OS command injection allows attackers to execute arbitrary system commands.',
            'xss': 'Cross-site scripting vulnerability allows injection of malicious scripts.',
            'buffer-overflow': 'Buffer overflow vulnerability may allow arbitrary code execution.',
            'csrf': 'Cross-site request forgery vulnerability allows unauthorized actions.',
            'path-traversal': 'Path traversal vulnerability allows access to unauthorized files.',
            'unrestricted-upload': 'Unrestricted file upload may allow malicious file execution.',
            'hardcoded-credentials': 'Hard-coded credentials pose a security risk.',
            'improper-authorization': 'Improper authorization may allow unauthorized access.',
            'incorrect-permissions': 'Incorrect file permissions may expose sensitive data.',
            'info-exposure': 'Information exposure may reveal sensitive system details.',
            'weak-crypto': 'Weak cryptographic algorithms provide insufficient protection.',
            'integer-overflow': 'Integer overflow may lead to unexpected behavior.',
            'null-pointer': 'NULL pointer dereference may cause application crashes.',
            'code-injection': 'Code injection allows execution of arbitrary code.',
            'xxe': 'XML External Entity vulnerability allows reading of arbitrary files.',
            'ssrf': 'Server-side request forgery allows unauthorized network requests.',
            'deserialization': 'Insecure deserialization may allow remote code execution.',
            'oob-read': 'Out-of-bounds read may cause information disclosure.',
            'input-validation': 'Improper input validation may lead to various attacks.'
        };
        return descMap[vulnType] || 'Security vulnerability detected.';
    }
    getCWE(vulnType) {
        const cweMap = {
            'sql-injection': 'CWE-89',
            'command-injection': 'CWE-78',
            'xss': 'CWE-79',
            'buffer-overflow': 'CWE-120',
            'csrf': 'CWE-352',
            'path-traversal': 'CWE-22',
            'unrestricted-upload': 'CWE-434',
            'hardcoded-credentials': 'CWE-798',
            'improper-authorization': 'CWE-285',
            'incorrect-permissions': 'CWE-732',
            'info-exposure': 'CWE-209',
            'weak-crypto': 'CWE-327',
            'integer-overflow': 'CWE-190',
            'null-pointer': 'CWE-476',
            'code-injection': 'CWE-94',
            'xxe': 'CWE-611',
            'ssrf': 'CWE-918',
            'deserialization': 'CWE-502',
            'oob-read': 'CWE-125',
            'input-validation': 'CWE-20'
        };
        return cweMap[vulnType] || 'CWE-noinfo';
    }
    getRecommendation(vulnType) {
        const recMap = {
            'sql-injection': 'Use parameterized queries or prepared statements.',
            'command-injection': 'Validate and sanitize all user input before using in system commands.',
            'xss': 'Encode output and validate input to prevent script injection.',
            'buffer-overflow': 'Use safe string functions and validate buffer boundaries.',
            'csrf': 'Implement CSRF tokens and validate referrer headers.',
            'path-traversal': 'Validate and sanitize file paths, use allow-lists.',
            'unrestricted-upload': 'Validate file types, extensions, and content.',
            'hardcoded-credentials': 'Use environment variables or secure credential storage.',
            'improper-authorization': 'Implement proper access control checks.',
            'incorrect-permissions': 'Set restrictive file and directory permissions.',
            'info-exposure': 'Disable debug mode and error reporting in production.',
            'weak-crypto': 'Use strong, modern cryptographic algorithms.',
            'integer-overflow': 'Validate numeric input ranges and use safe arithmetic.',
            'null-pointer': 'Check for null values before dereferencing.',
            'code-injection': 'Never execute user-controlled data as code.',
            'xxe': 'Disable external entity processing in XML parsers.',
            'ssrf': 'Validate and restrict server-side request destinations.',
            'deserialization': 'Avoid deserializing untrusted data or use safe formats.',
            'oob-read': 'Validate array bounds and input ranges.',
            'input-validation': 'Implement comprehensive input validation and sanitization.'
        };
        return recMap[vulnType] || 'Follow security best practices.';
    }
    isFixable(vulnType) {
        const fixableTypes = [
            'hardcoded-credentials',
            'info-exposure',
            'weak-crypto',
            'incorrect-permissions',
            'input-validation'
        ];
        return fixableTypes.includes(vulnType);
    }
}
exports.SansDetector = SansDetector;
//# sourceMappingURL=sansDetector.js.map