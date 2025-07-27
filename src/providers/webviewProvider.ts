import * as vscode from 'vscode';
import { ScanResult } from '../scanner/vulnerabilityScanner';

export class VulnerabilityWebviewProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = 'vulnerabilityReport';
    private _view?: vscode.WebviewView;
    private results: ScanResult[] = [];

    constructor(private readonly _extensionUri: vscode.Uri) {}

    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ) {
        this._view = webviewView;

        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this._extensionUri]
        };

        webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

        webviewView.webview.onDidReceiveMessage(data => {
            switch (data.type) {
                case 'fixVulnerability':
                    vscode.commands.executeCommand('vulnerabilityScanner.fixVulnerability', data.vulnerability);
                    break;
                case 'fixWithAI':
                    vscode.commands.executeCommand('securityTreeProvider.fixWithAI', data.vulnerability);
                    break;
                case 'openFile':
                    vscode.commands.executeCommand('vscode.open', 
                        vscode.Uri.file(data.file), 
                        { selection: new vscode.Range(data.line - 1, data.column, data.line - 1, data.column + data.length) }
                    );
                    break;
            }
        });
    }

    public updateResults(results: ScanResult[]) {
        this.results = results;
        if (this._view) {
            this._view.webview.postMessage({ type: 'updateResults', results: results });
        }
    }

    public show() {
        if (this._view) {
            this._view.show?.(true);
        }
    }

    private _getHtmlForWebview(webview: vscode.Webview) {
        return `<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Report</title>
            <style>
                body {
                    font-family: var(--vscode-font-family);
                    font-size: var(--vscode-font-size);
                    line-height: 1.6;
                    color: var(--vscode-foreground);
                    background-color: var(--vscode-editor-background);
                    margin: 0;
                    padding: 16px;
                }
                
                .header {
                    display: flex;
                    align-items: center;
                    margin-bottom: 20px;
                    padding-bottom: 10px;
                    border-bottom: 1px solid var(--vscode-panel-border);
                }
                
                .header h1 {
                    margin: 0;
                    color: var(--vscode-foreground);
                }
                
                .summary {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
                    gap: 12px;
                    margin-bottom: 24px;
                }
                
                .summary-card {
                    background: var(--vscode-button-background);
                    border: 1px solid var(--vscode-panel-border);
                    border-radius: 4px;
                    padding: 12px;
                    text-align: center;
                }
                
                .summary-card h3 {
                    margin: 0 0 4px 0;
                    font-size: 24px;
                    font-weight: bold;
                }
                
                .summary-card p {
                    margin: 0;
                    font-size: 12px;
                    opacity: 0.8;
                }
                
                .critical { color: #ff4444; }
                .high { color: #ff8800; }
                .medium { color: #ffaa00; }
                .low { color: #44aa44; }
                
                .vulnerability-card {
                    background: var(--vscode-editor-background);
                    border: 1px solid var(--vscode-panel-border);
                    border-radius: 4px;
                    margin-bottom: 12px;
                    overflow: hidden;
                }
                
                .vulnerability-header {
                    background: var(--vscode-button-background);
                    padding: 12px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    cursor: pointer;
                }
                
                .vulnerability-title {
                    font-weight: bold;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }
                
                .severity-badge {
                    font-size: 10px;
                    padding: 2px 6px;
                    border-radius: 2px;
                    font-weight: bold;
                    text-transform: uppercase;
                }
                
                .severity-badge.critical {
                    background: #ff4444;
                    color: white;
                }
                
                .severity-badge.high {
                    background: #ff8800;
                    color: white;
                }
                
                .severity-badge.medium {
                    background: #ffaa00;
                    color: black;
                }
                
                .severity-badge.low {
                    background: #44aa44;
                    color: white;
                }
                
                .vulnerability-details {
                    padding: 12px;
                    display: none;
                }
                
                .vulnerability-details.show {
                    display: block;
                }
                
                .code-snippet {
                    background: var(--vscode-textCodeBlock-background);
                    border: 1px solid var(--vscode-panel-border);
                    border-radius: 4px;
                    padding: 8px;
                    margin: 8px 0;
                    font-family: var(--vscode-editor-font-family);
                    font-size: var(--vscode-editor-font-size);
                    overflow-x: auto;
                }
                
                .actions {
                    display: flex;
                    gap: 8px;
                    margin-top: 12px;
                }
                
                .btn {
                    background: var(--vscode-button-background);
                    color: var(--vscode-button-foreground);
                    border: none;
                    padding: 6px 12px;
                    border-radius: 2px;
                    cursor: pointer;
                    font-size: 12px;
                }
                
                .btn:hover {
                    background: var(--vscode-button-hoverBackground);
                }
                
                .btn-fix {
                    background: var(--vscode-button-background);
                }
                
                .btn-open {
                    background: var(--vscode-button-secondaryBackground);
                    color: var(--vscode-button-secondaryForeground);
                }
                
                .btn-ai-fix {
                    background: #4CAF50;
                    color: white;
                }
                
                .btn-ai-fix:hover {
                    background: #45a049;
                }
                
                .empty-state {
                    text-align: center;
                    padding: 40px;
                    color: var(--vscode-descriptionForeground);
                }
                
                .empty-state h2 {
                    color: var(--vscode-foreground);
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ Security Report</h1>
            </div>
            
            <div id="content">
                <div class="empty-state">
                    <h2>No Scan Results</h2>
                    <p>Run a security scan to see vulnerability reports here.</p>
                </div>
            </div>

            <script>
                const vscode = acquireVsCodeApi();
                let currentResults = [];

                window.addEventListener('message', event => {
                    const message = event.data;
                    switch (message.type) {
                        case 'updateResults':
                            currentResults = message.results;
                            renderResults();
                            break;
                    }
                });

                function renderResults() {
                    const content = document.getElementById('content');
                    
                    if (!currentResults || currentResults.length === 0) {
                        content.innerHTML = \`
                            <div class="empty-state">
                                <h2>✅ No Vulnerabilities Found</h2>
                                <p>Your code looks secure! No vulnerabilities were detected.</p>
                            </div>
                        \`;
                        return;
                    }

                    const totalVulns = currentResults.reduce((sum, file) => sum + file.vulnerabilities.length, 0);
                    const criticalCount = getTotalBySeverity('critical');
                    const highCount = getTotalBySeverity('high');
                    const mediumCount = getTotalBySeverity('medium');
                    const lowCount = getTotalBySeverity('low');

                    content.innerHTML = \`
                        <div class="summary">
                            <div class="summary-card">
                                <h3>\${totalVulns}</h3>
                                <p>Total Issues</p>
                            </div>
                            <div class="summary-card">
                                <h3 class="critical">\${criticalCount}</h3>
                                <p>Critical</p>
                            </div>
                            <div class="summary-card">
                                <h3 class="high">\${highCount}</h3>
                                <p>High</p>
                            </div>
                            <div class="summary-card">
                                <h3 class="medium">\${mediumCount}</h3>
                                <p>Medium</p>
                            </div>
                            <div class="summary-card">
                                <h3 class="low">\${lowCount}</h3>
                                <p>Low</p>
                            </div>
                        </div>
                        
                        <div class="vulnerabilities">
                            \${renderVulnerabilities()}
                        </div>
                    \`;

                    // Add click handlers
                    document.querySelectorAll('.vulnerability-header').forEach(header => {
                        header.addEventListener('click', () => {
                            const details = header.nextElementSibling;
                            details.classList.toggle('show');
                        });
                    });
                }

                function renderVulnerabilities() {
                    let html = '';
                    
                    const allVulnerabilities = [];
                    currentResults.forEach(result => {
                        result.vulnerabilities.forEach(vuln => {
                            allVulnerabilities.push({...vuln, fileName: result.file.split('/').pop()});
                        });
                    });

                    // Sort by severity
                    const severityOrder = { 'critical': 0, 'high': 1, 'medium': 2, 'low': 3 };
                    allVulnerabilities.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

                    allVulnerabilities.forEach((vuln, index) => {
                        html += \`
                            <div class="vulnerability-card">
                                <div class="vulnerability-header">
                                    <div class="vulnerability-title">
                                        <span class="severity-badge \${vuln.severity}">\${vuln.severity}</span>
                                        <span>\${vuln.title}</span>
                                    </div>
                                    <small>\${vuln.fileName}:\${vuln.line}</small>
                                </div>
                                <div class="vulnerability-details">
                                    <p><strong>Category:</strong> \${vuln.category}</p>
                                    <p><strong>Description:</strong> \${vuln.description}</p>
                                    <p><strong>CWE:</strong> \${vuln.cwe || 'N/A'}</p>
                                    
                                    <div class="code-snippet">
                                        <strong>Line \${vuln.line}:</strong><br>
                                        <code>\${vuln.code}</code>
                                    </div>
                                    
                                    <p><strong>Recommendation:</strong> \${vuln.recommendation}</p>
                                    
                                    <div class="actions">
                                        <button class="btn btn-open" onclick="openFile('\${vuln.file}', \${vuln.line}, \${vuln.column}, \${vuln.length})">
                                            📍 Go to Code
                                        </button>
                                        \${vuln.fixable ? \`<button class="btn btn-fix" onclick="fixVulnerability('\${vuln.id}')">🔧 Auto Fix</button>\` : ''}
                                        <button class="btn btn-ai-fix" onclick="fixWithAI('\${vuln.id}')">🧠 Fix with AI</button>
                                    </div>
                                </div>
                            </div>
                        \`;
                    });

                    return html;
                }

                function getTotalBySeverity(severity) {
                    return currentResults.reduce((sum, file) => 
                        sum + file.vulnerabilities.filter(v => v.severity === severity).length, 0);
                }

                function openFile(file, line, column, length) {
                    vscode.postMessage({
                        type: 'openFile',
                        file: file,
                        line: line,
                        column: column,
                        length: length
                    });
                }

                function fixVulnerability(vulnId) {
                    const vuln = currentResults
                        .flatMap(r => r.vulnerabilities)
                        .find(v => v.id === vulnId);
                    
                    if (vuln) {
                        vscode.postMessage({
                            type: 'fixVulnerability',
                            vulnerability: vuln
                        });
                    }
                }

                function fixWithAI(vulnId) {
                    const vuln = currentResults
                        .flatMap(r => r.vulnerabilities)
                        .find(v => v.id === vulnId);
                    
                    if (vuln) {
                        vscode.postMessage({
                            type: 'fixWithAI',
                            vulnerability: vuln
                        });
                    }
                }
            </script>
        </body>
        </html>`;
    }
}