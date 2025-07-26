import * as vscode from 'vscode';
import { ScanResult, Vulnerability } from '../scanner/vulnerabilityScanner';

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
                const item = new SecurityTreeItem(
                    `${vuln.title} (Line ${vuln.line})`,
                    vscode.TreeItemCollapsibleState.None,
                    'vulnerability',
                    element.scanResult,
                    [vuln]
                );
                
                item.tooltip = `${vuln.description}\n\nRecommendation: ${vuln.recommendation}`;
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

                if (vuln.fixable) {
                    item.contextValue = 'fixable-vulnerability';
                }

                items.push(item);
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
        
        // Set icons based on context
        switch (contextValue) {
            case 'summary':
                this.iconPath = new vscode.ThemeIcon('info');
                break;
            case 'file':
                this.iconPath = new vscode.ThemeIcon('file');
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