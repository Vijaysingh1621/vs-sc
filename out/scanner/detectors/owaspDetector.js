"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OwaspDetector = void 0;
class OwaspDetector {
    constructor() {
        this.patterns = {
            // A01:2021 – Broken Access Control
            'broken-access-control': [
                /(?:admin|root|superuser)\s*=\s*true/gi,
                /bypass.*auth/gi,
                /skip.*permission/gi,
                /\.hasRole\(\s*["'].*["']\s*\)\s*\|\|\s*true/gi
            ],
            // A02:2021 – Cryptographic Failures
            'crypto-failures': [
                /md5\s*\(/gi,
                /sha1\s*\(/gi,
                /des\s*\(/gi,
                /rc4\s*\(/gi,
                /password\s*=\s*["'][^"']*["']/gi,
                /secret\s*=\s*["'][^"']*["']/gi
            ],
            // A03:2021 – Injection
            'injection': [
                /\$_(?:GET|POST|REQUEST|COOKIE)\[.*?\].*?(?:mysql_query|mysqli_query|pg_query)/gi,
                /execute\s*\(\s*["'].*?\+.*?["']/gi,
                /query\s*\(\s*["'].*?\+.*?["']/gi,
                /eval\s*\(/gi,
                /exec\s*\(/gi,
                /system\s*\(/gi
            ],
            // A04:2021 – Insecure Design
            'insecure-design': [
                /setTimeout\s*\(\s*["'].*?["']\s*,/gi,
                /setInterval\s*\(\s*["'].*?["']\s*,/gi,
                /Function\s*\(\s*["'].*?["']\s*\)/gi
            ],
            // A05:2021 – Security Misconfiguration
            'security-misconfiguration': [
                /debug\s*=\s*true/gi,
                /development\s*=\s*true/gi,
                /cors\s*:\s*{.*origin\s*:\s*["']\*["']/gi,
                /x-powered-by/gi
            ],
            // A06:2021 – Vulnerable Components
            'vulnerable-components': [
                /jquery.*[12]\./gi,
                /angular.*1\.[0-6]/gi,
                /react.*1[0-5]\./gi
            ],
            // A07:2021 – Authentication Failures
            'auth-failures': [
                /password\s*==\s*["'][^"']*["']/gi,
                /if\s*\(\s*user\s*\)/gi,
                /session\s*=\s*{}/gi,
                /no.*password.*validation/gi
            ],
            // A08:2021 – Software Integrity Failures
            'integrity-failures': [
                /http:\/\/.*\.js/gi,
                /cdn\..*\.com.*http:/gi,
                /script.*src.*http:/gi
            ],
            // A09:2021 – Logging Failures
            'logging-failures': [
                /console\.log\s*\(\s*.*password/gi,
                /console\.log\s*\(\s*.*token/gi,
                /print\s*\(\s*.*password/gi,
                /echo\s*.*password/gi
            ],
            // A10:2021 – Server Side Request Forgery
            'ssrf': [
                /fetch\s*\(\s*req\.query\./gi,
                /request\s*\(\s*req\.body\./gi,
                /axios\s*\(\s*.*req\./gi,
                /urllib.*req\./gi
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
                        id: `owasp-${vulnType}-${lineNumber}-${column}`,
                        type: vulnType,
                        category: 'OWASP',
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
            'broken-access-control': 'critical',
            'crypto-failures': 'high',
            'injection': 'critical',
            'insecure-design': 'high',
            'security-misconfiguration': 'medium',
            'vulnerable-components': 'high',
            'auth-failures': 'critical',
            'integrity-failures': 'medium',
            'logging-failures': 'low',
            'ssrf': 'high'
        };
        return severityMap[vulnType] || 'medium';
    }
    getTitle(vulnType) {
        const titleMap = {
            'broken-access-control': 'Broken Access Control',
            'crypto-failures': 'Cryptographic Failures',
            'injection': 'Injection Vulnerability',
            'insecure-design': 'Insecure Design',
            'security-misconfiguration': 'Security Misconfiguration',
            'vulnerable-components': 'Vulnerable Components',
            'auth-failures': 'Authentication Failures',
            'integrity-failures': 'Software Integrity Failures',
            'logging-failures': 'Security Logging Failures',
            'ssrf': 'Server-Side Request Forgery'
        };
        return titleMap[vulnType] || 'Security Vulnerability';
    }
    getDescription(vulnType) {
        const descMap = {
            'broken-access-control': 'Access control bypass detected. Users may be able to access unauthorized functionality.',
            'crypto-failures': 'Weak cryptographic implementation detected. Sensitive data may be exposed.',
            'injection': 'Code injection vulnerability detected. Untrusted input is being executed.',
            'insecure-design': 'Insecure design pattern detected. The application architecture has security flaws.',
            'security-misconfiguration': 'Security misconfiguration detected. Default or insecure settings are in use.',
            'vulnerable-components': 'Vulnerable component detected. Outdated dependencies with known vulnerabilities.',
            'auth-failures': 'Authentication weakness detected. Invalid authentication implementation.',
            'integrity-failures': 'Software integrity issue detected. Untrusted sources or missing integrity checks.',
            'logging-failures': 'Logging security issue detected. Sensitive data is being logged inappropriately.',
            'ssrf': 'Server-side request forgery detected. User input is used in server-side requests.'
        };
        return descMap[vulnType] || 'Security vulnerability detected.';
    }
    getCWE(vulnType) {
        const cweMap = {
            'broken-access-control': 'CWE-862',
            'crypto-failures': 'CWE-327',
            'injection': 'CWE-89',
            'insecure-design': 'CWE-1021',
            'security-misconfiguration': 'CWE-16',
            'vulnerable-components': 'CWE-1104',
            'auth-failures': 'CWE-287',
            'integrity-failures': 'CWE-345',
            'logging-failures': 'CWE-532',
            'ssrf': 'CWE-918'
        };
        return cweMap[vulnType] || 'CWE-noinfo';
    }
    getRecommendation(vulnType) {
        const recMap = {
            'broken-access-control': 'Implement proper access control checks and deny by default.',
            'crypto-failures': 'Use strong, up-to-date cryptographic algorithms and proper key management.',
            'injection': 'Use parameterized queries, input validation, and sanitization.',
            'insecure-design': 'Implement secure design patterns and threat modeling.',
            'security-misconfiguration': 'Use security hardening guides and remove unnecessary features.',
            'vulnerable-components': 'Update to latest versions and monitor for vulnerabilities.',
            'auth-failures': 'Implement multi-factor authentication and proper session management.',
            'integrity-failures': 'Use digital signatures and verify the integrity of software components.',
            'logging-failures': 'Avoid logging sensitive data and implement proper log monitoring.',
            'ssrf': 'Validate and sanitize user input used in server-side requests.'
        };
        return recMap[vulnType] || 'Follow security best practices.';
    }
    isFixable(vulnType) {
        const fixableTypes = [
            'crypto-failures',
            'security-misconfiguration',
            'logging-failures',
            'vulnerable-components'
        ];
        return fixableTypes.includes(vulnType);
    }
}
exports.OwaspDetector = OwaspDetector;
//# sourceMappingURL=owaspDetector.js.map