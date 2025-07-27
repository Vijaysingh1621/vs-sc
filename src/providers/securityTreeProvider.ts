import * as vscode from 'vscode';
import { ScanResult, Vulnerability } from '../scanner/vulnerabilityScanner';
import axios from 'axios';

export class SecurityTreeProvider implements vscode.TreeDataProvider<SecurityTreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<SecurityTreeItem | undefined | null | void> = new vscode.EventEmitter<SecurityTreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<SecurityTreeItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private vulnerabilities: ScanResult[] = [];

    updateVulnerabilities(results: ScanResult[]): void {
        this.vulnerabilities = results;
        this._onDidChangeTreeData.fire();
    }

    updateFileVulnerabilities(filePath: string, result: ScanResult): void {
        const existingIndex = this.vulnerabilities.findIndex(r => r.file === filePath);
        if (existingIndex >= 0) {
            if (result.vulnerabilities.length > 0) {
                this.vulnerabilities[existingIndex] = result;
            } else {
                this.vulnerabilities.splice(existingIndex, 1);
            }
        } else if (result.vulnerabilities.length > 0) {
            this.vulnerabilities.push(result);
        }
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: SecurityTreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: SecurityTreeItem): Thenable<SecurityTreeItem[]> {
        if (!element) {
            // Root level - show summary and files
            const items: SecurityTreeItem[] = [];
            
            if (this.vulnerabilities.length === 0) {
                items.push(new SecurityTreeItem(
                    'No vulnerabilities found',
                    vscode.TreeItemCollapsibleState.None,
                    'info'
                ));
                return Promise.resolve(items);
            }

            // Summary
            const totalVulns = this.vulnerabilities.reduce((sum, file) => sum + file.vulnerabilities.length, 0);
            const criticalCount = this.getTotalBySeverity('critical');
            const highCount = this.getTotalBySeverity('high');
            
            items.push(new SecurityTreeItem(
                `${totalVulns} vulnerabilities found (${criticalCount} critical, ${highCount} high)`,
                vscode.TreeItemCollapsibleState.None,
                'summary'
            ));

            // Files with vulnerabilities
            for (const result of this.vulnerabilities) {
                const fileName = result.file.split('/').pop() || result.file;
                items.push(new SecurityTreeItem(
                    `${fileName} (${result.vulnerabilities.length})`,
                    vscode.TreeItemCollapsibleState.Collapsed,
                    'file',
                    result
                ));
            }

            return Promise.resolve(items);
        } else if (element.contextValue === 'file' && element.scanResult) {
            // Show vulnerabilities for a file
            const items: SecurityTreeItem[] = [];
            const vulns = element.scanResult.vulnerabilities;
            
            // Add "Fix All with AI" button at the top
            if (vulns.length > 0) {
                items.push(new SecurityTreeItem(
                    `🤖 Fix All with AI (${vulns.length} issues)`,
                    vscode.TreeItemCollapsibleState.None,
                    'fix-all-ai',
                    element.scanResult
                ));
            }
            
            // Group by severity
            const critical = vulns.filter(v => v.severity === 'critical');
            const high = vulns.filter(v => v.severity === 'high');
            const medium = vulns.filter(v => v.severity === 'medium');
            const low = vulns.filter(v => v.severity === 'low');

            if (critical.length > 0) {
                items.push(new SecurityTreeItem(
                    `Critical (${critical.length})`,
                    vscode.TreeItemCollapsibleState.Collapsed,
                    'severity',
                    element.scanResult,
                    critical
                ));
            }

            if (high.length > 0) {
                items.push(new SecurityTreeItem(
                    `High (${high.length})`,
                    vscode.TreeItemCollapsibleState.Collapsed,
                    'severity',
                    element.scanResult,
                    high
                ));
            }

            if (medium.length > 0) {
                items.push(new SecurityTreeItem(
                    `Medium (${medium.length})`,
                    vscode.TreeItemCollapsibleState.Collapsed,
                    'severity',
                    element.scanResult,
                    medium
                ));
            }

            if (low.length > 0) {
                items.push(new SecurityTreeItem(
                    `Low (${low.length})`,
                    vscode.TreeItemCollapsibleState.Collapsed,
                    'severity',
                    element.scanResult,
                    low
                ));
            }

            return Promise.resolve(items);
        } else if (element.contextValue === 'severity' && element.vulnerabilities) {
            // Show individual vulnerabilities
            const items: SecurityTreeItem[] = [];
            for (const vuln of element.vulnerabilities) {
                const contextVal = vuln.fixable ? 'fixable-vulnerability' : 'vulnerability';
                const item = new SecurityTreeItem(
                    `${vuln.title} (Line ${vuln.line})`,
                    vscode.TreeItemCollapsibleState.None,
                    contextVal,
                    element.scanResult,
                    [vuln]
                );

                // Deterministic security score calculation based on severity and type
                const baseScore = getBaseScore(vuln.severity);
                const typeScore = getTypeScore(vuln.type);
                const score = Math.max(1, Math.min(10, baseScore + typeScore));

                // Enhanced tooltip UI (Markdown) with Security Score and AI Fix button
                let md = new vscode.MarkdownString();
                md.appendMarkdown('---\n');
                md.appendMarkdown(`**$(bug) ${vuln.title}**  (Line ${vuln.line})\n\n`);
                md.appendMarkdown(`> ${vuln.description}\n\n`);
                md.appendMarkdown(`**Severity:** $(flame) ${capitalize(vuln.severity)}  `);
                md.appendMarkdown(`**Security Score:** $(star-full) **${score}/10**\n`);
                if (vuln.cwe) md.appendMarkdown(`**CWE:** ${vuln.cwe}\n`);
                md.appendMarkdown(`**Category:** ${vuln.category}\n`);
                md.appendMarkdown('---\n');
                md.appendMarkdown('**Recommendation:**\n');
                md.appendMarkdown(`- ${vuln.recommendation}\n`);
                md.appendMarkdown('\n---\n');
                md.appendMarkdown('$(file-code) **Code:**\n\n');
                md.appendCodeblock(vuln.code);
                md.appendMarkdown('\n---\n');
                // Always show Fix with AI button, on a new line, with extra spacing for visibility
                md.appendMarkdown(`\n[🧠 **Fix with AI**](command:securityTreeProvider.fixWithAI?${encodeURIComponent(JSON.stringify(vuln))} "Let Gemini AI suggest a fix for this vulnerability and apply it in your code.")\n`);
                md.isTrusted = true;
                item.tooltip = md;

                item.command = {
                    command: 'vscode.open',
                    title: 'Open',
                    arguments: [
                        vscode.Uri.file(vuln.file),
                        {
                            selection: new vscode.Range(
                                vuln.line - 1,
                                vuln.column,
                                vuln.line - 1,
                                vuln.column + vuln.length
                            )
                        }
                    ]
                };

                items.push(item);
            }

            // --- Gemini AI Fix Command Registration ---
            if (!(globalThis as any)._securityTreeProviderFixWithAIRegistered) {
                (globalThis as any)._securityTreeProviderFixWithAIRegistered = true;
                vscode.commands.registerCommand('securityTreeProvider.fixWithAI', async (vuln: Vulnerability) => {
                    try {
                        const editor = await vscode.window.showTextDocument(vscode.Uri.file(vuln.file));
                        const document = editor.document;
                        const range = new vscode.Range(
                            vuln.line - 1,
                            vuln.column,
                            vuln.line - 1,
                            vuln.column + vuln.length
                        );
                        const originalCode = document.getText(range);

                        vscode.window.withProgress({
                            location: vscode.ProgressLocation.Notification,
                            title: 'Gemini AI: Generating fix for vulnerability...'
                        }, async () => {
                            // Call Gemini API via Axios
                            const apiKey = process.env.GEMINI_API_KEY || '';
                            if (!apiKey) {
                                vscode.window.showErrorMessage('Gemini API key not set. Please set GEMINI_API_KEY in your environment.');
                                return;
                            }
                            const prompt = `You are a security code assistant. Given the following vulnerable code, provide a secure fixed version.\n\nVulnerable code:\n${originalCode}\n\nVulnerability: ${vuln.title}\nDescription: ${vuln.description}\nRecommendation: ${vuln.recommendation}\n\nReturn ONLY the fixed code, no explanation.`;
                            try {
                                const response = await axios.post(
                                    'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent',
                                    {
                                        contents: [{ parts: [{ text: prompt }] }]
                                    },
                                    {
                                        headers: { 'Content-Type': 'application/json' },
                                        params: { key: apiKey }
                                    }
                                );
                                const fixedCode = response.data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim();
                                if (fixedCode && fixedCode !== originalCode) {
                                    const edit = new vscode.WorkspaceEdit();
                                    edit.replace(document.uri, range, fixedCode);
                                    await vscode.workspace.applyEdit(edit);
                                    await document.save();
                                    vscode.window.showInformationMessage('Gemini AI fix applied!');
                                } else {
                                    vscode.window.showWarningMessage('Gemini AI did not return a fix or the fix is identical to the original code.');
                                }
                            } catch (err: any) {
                                vscode.window.showErrorMessage('Gemini API error: ' + (err?.message || err));
                            }
                        });
                    } catch (e: any) {
                        vscode.window.showErrorMessage('Failed to apply Gemini AI fix: ' + (e?.message || e));
                    }
                });

                // Register Fix All with AI command
                vscode.commands.registerCommand('securityTreeProvider.fixAllWithAI', async (scanResult: ScanResult) => {
                    try {
                        const editor = await vscode.window.showTextDocument(vscode.Uri.file(scanResult.file));
                        const document = editor.document;
                        const vulnerabilities = scanResult.vulnerabilities;

                        const result = await vscode.window.showInformationMessage(
                            `Fix all ${vulnerabilities.length} vulnerabilities with Gemini AI?`,
                            'Yes', 'No'
                        );

                        if (result !== 'Yes') return;

                        vscode.window.withProgress({
                            location: vscode.ProgressLocation.Notification,
                            title: `Gemini AI: Fixing ${vulnerabilities.length} vulnerabilities...`,
                            cancellable: true
                        }, async (progress, token) => {
                            const apiKey = process.env.GEMINI_API_KEY || '';
                            if (!apiKey) {
                                vscode.window.showErrorMessage('Gemini API key not set. Please set GEMINI_API_KEY in your environment.');
                                return;
                            }

                            let fixedCount = 0;
                            const totalVulns = vulnerabilities.length;

                            // Sort vulnerabilities by line number (descending) to avoid offset issues
                            const sortedVulns = vulnerabilities.sort((a, b) => b.line - a.line);

                            for (let i = 0; i < sortedVulns.length; i++) {
                                if (token.isCancellationRequested) break;

                                const vuln = sortedVulns[i];
                                progress.report({
                                    increment: (100 / totalVulns),
                                    message: `Fixing ${vuln.title} (${i + 1}/${totalVulns})`
                                });

                                try {
                                    const range = new vscode.Range(
                                        vuln.line - 1,
                                        vuln.column,
                                        vuln.line - 1,
                                        vuln.column + vuln.length
                                    );
                                    const originalCode = document.getText(range);

                                    const prompt = `You are a security code assistant. Given the following vulnerable code, provide a secure fixed version.\n\nVulnerable code:\n${originalCode}\n\nVulnerability: ${vuln.title}\nDescription: ${vuln.description}\nRecommendation: ${vuln.recommendation}\n\nReturn ONLY the fixed code, no explanation.`;

                                    const response = await axios.post(
                                        'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent',
                                        {
                                            contents: [{ parts: [{ text: prompt }] }]
                                        },
                                        {
                                            headers: { 'Content-Type': 'application/json' },
                                            params: { key: apiKey }
                                        }
                                    );

                                    const fixedCode = response.data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim();
                                    if (fixedCode && fixedCode !== originalCode) {
                                        const edit = new vscode.WorkspaceEdit();
                                        edit.replace(document.uri, range, fixedCode);
                                        await vscode.workspace.applyEdit(edit);
                                        fixedCount++;
                                    }

                                    // Small delay to avoid rate limiting
                                    await new Promise(resolve => setTimeout(resolve, 500));
                                } catch (err: any) {
                                    console.error(`Failed to fix vulnerability ${vuln.title}:`, err);
                                }
                            }

                            await document.save();
                            vscode.window.showInformationMessage(`Gemini AI fixed ${fixedCount}/${totalVulns} vulnerabilities!`);
                        });
                    } catch (e: any) {
                        vscode.window.showErrorMessage('Failed to apply Gemini AI fixes: ' + (e?.message || e));
                    }
                });
            }

            // --- Security Score Calculation Helpers ---
            function getBaseScore(severity: string): number {
                switch (severity) {
                    case 'critical': return 9;
                    case 'high': return 7;
                    case 'medium': return 5;
                    case 'low': return 3;
                    default: return 1;
                }
            }

            function getTypeScore(type: string): number {
                // Deterministic mapping for known types (OWASP/SANS)
                // Higher risk types get a higher bonus
                const typeMap: { [key: string]: number } = {
                    // OWASP
                    'broken-access-control': 1,
                    'crypto-failures': 1,
                    'injection': 2,
                    'insecure-design': 1,
                    'security-misconfiguration': 0,
                    'vulnerable-components': 1,
                    'auth-failures': 2,
                    'integrity-failures': 1,
                    'logging-failures': 0,
                    'ssrf': 2,
                    // SANS
                    'sql-injection': 2,
                    'command-injection': 2,
                    'xss': 1,
                    'buffer-overflow': 2,
                    'csrf': 1,
                    'path-traversal': 1,
                    'unrestricted-upload': 1,
                    'hardcoded-credentials': 1,
                    'improper-authorization': 1,
                    'incorrect-permissions': 0,
                    'info-exposure': 0,
                    'weak-crypto': 0,
                    'integer-overflow': 1,
                    'null-pointer': 0,
                    'code-injection': 2,
                    'xxe': 1,
                    'deserialization': 2,
                    'oob-read': 0,
                    'input-validation': 1
                };
                return typeMap[type] ?? 0;
            }

            function capitalize(str: string): string {
                return str.charAt(0).toUpperCase() + str.slice(1);
            }

            return Promise.resolve(items);
        }

        return Promise.resolve([]);
    }

    private getTotalBySeverity(severity: string): number {
        return this.vulnerabilities.reduce((sum, file) => 
            sum + file.vulnerabilities.filter(v => v.severity === severity).length, 0);
    }
}

export class SecurityTreeItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly contextValue: string,
        public readonly scanResult?: ScanResult,
        public readonly vulnerabilities?: Vulnerability[]
    ) {
        super(label, collapsibleState);
        
        this.contextValue = contextValue;
        
        // Set icons and commands based on context
        switch (contextValue) {
            case 'summary':
                this.iconPath = new vscode.ThemeIcon('info');
                break;
            case 'file':
                this.iconPath = new vscode.ThemeIcon('file');
                break;
            case 'fix-all-ai':
                this.iconPath = new vscode.ThemeIcon('robot');
                this.command = {
                    command: 'securityTreeProvider.fixAllWithAI',
                    title: 'Fix All with AI',
                    arguments: [scanResult]
                };
                break;
            case 'severity':
                if (label.includes('Critical')) {
                    this.iconPath = new vscode.ThemeIcon('error');
                } else if (label.includes('High')) {
                    this.iconPath = new vscode.ThemeIcon('warning');
                } else if (label.includes('Medium')) {
                    this.iconPath = new vscode.ThemeIcon('info');
                } else {
                    this.iconPath = new vscode.ThemeIcon('circle-outline');
                }
                break;
            case 'vulnerability':
            case 'fixable-vulnerability':
                this.iconPath = new vscode.ThemeIcon('bug');
                break;
            default:
                this.iconPath = new vscode.ThemeIcon('shield');
        }
    }
}