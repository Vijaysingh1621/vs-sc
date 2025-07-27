import * as vscode from 'vscode';
import { VulnerabilityScanner } from './scanner/vulnerabilityScanner';
import { SecurityTreeProvider } from './providers/securityTreeProvider';
import { VulnerabilityWebviewProvider } from './providers/webviewProvider';
import { DiagnosticsManager } from './diagnostics/diagnosticsManager';

let scanner: VulnerabilityScanner;
let treeProvider: SecurityTreeProvider;
let webviewProvider: VulnerabilityWebviewProvider;
let diagnosticsManager: DiagnosticsManager;

export function activate(context: vscode.ExtensionContext) {
    console.log('Vulnerability Scanner Pro is now active!');

    // Initialize components
    scanner = new VulnerabilityScanner();
    treeProvider = new SecurityTreeProvider();
    webviewProvider = new VulnerabilityWebviewProvider(context.extensionUri);
    diagnosticsManager = new DiagnosticsManager();

    // Register tree view
    const treeView = vscode.window.createTreeView('vulnerabilityScanner', {
        treeDataProvider: treeProvider,
        showCollapseAll: true
    });

    // Register webview provider
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(
            'vulnerabilityReport',
            webviewProvider
        )
    );

    // Register commands
    const scanWorkspaceCommand = vscode.commands.registerCommand(
        'vulnerabilityScanner.scanWorkspace',
        async () => {
            await scanWorkspace();
        }
    );

    const scanFileCommand = vscode.commands.registerCommand(
        'vulnerabilityScanner.scanFile',
        async () => {
            const activeEditor = vscode.window.activeTextEditor;
            if (activeEditor) {
                await scanFile(activeEditor.document);
            }
        }
    );

    const fixVulnerabilityCommand = vscode.commands.registerCommand(
        'vulnerabilityScanner.fixVulnerability',
        async (vulnerability: any) => {
            await fixVulnerability(vulnerability);
        }
    );

    const showReportCommand = vscode.commands.registerCommand(
        'vulnerabilityScanner.showReport',
        () => {
            webviewProvider.show();
        }
    );

    const setupGeminiCommand = vscode.commands.registerCommand(
        'vulnerabilityScanner.setupGemini',
        async () => {
            const apiKey = await vscode.window.showInputBox({
                prompt: 'Enter your Gemini API Key',
                password: true,
                placeHolder: 'Get your API key from https://makersuite.google.com/app/apikey'
            });
            
            if (apiKey) {
                // Store in VS Code settings
                await vscode.workspace.getConfiguration('vulnerabilityScanner').update('geminiApiKey', apiKey, vscode.ConfigurationTarget.Global);
                vscode.window.showInformationMessage('Gemini API key saved successfully!');
            }
        }
    );

    // Register event listeners
    const onDidSaveDocument = vscode.workspace.onDidSaveTextDocument(
        async (document) => {
            const config = vscode.workspace.getConfiguration('vulnerabilityScanner');
            if (config.get('enableAutoScan')) {
                await scanFile(document);
            }
        }
    );

    const onDidOpenTextDocument = vscode.workspace.onDidOpenTextDocument(
        async (document) => {
            if (document.uri.scheme === 'file') {
                await scanFile(document);
            }
        }
    );

    // Add subscriptions
    context.subscriptions.push(
        scanWorkspaceCommand,
        scanFileCommand,
        fixVulnerabilityCommand,
        showReportCommand,
        setupGeminiCommand,
        onDidSaveDocument,
        onDidOpenTextDocument,
        treeView
    );

    // Initial scan on startup
    const config = vscode.workspace.getConfiguration('vulnerabilityScanner');
    if (config.get('scanOnStartup')) {
        setTimeout(() => scanWorkspace(), 2000);
    }
}

async function scanWorkspace() {
    try {
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "Scanning workspace for vulnerabilities...",
            cancellable: true
        }, async (progress, token) => {
            const workspaceFolders = vscode.workspace.workspaceFolders;
            if (!workspaceFolders) return;

            const results = await scanner.scanWorkspace(workspaceFolders[0].uri.fsPath, token);
            
            // Update diagnostics
            diagnosticsManager.updateDiagnostics(results);
            
            // Update tree view
            treeProvider.updateVulnerabilities(results);
            
            // Update webview
            webviewProvider.updateResults(results);
            
            // Show summary
            const totalVulns = results.reduce((sum, file) => sum + file.vulnerabilities.length, 0);
            vscode.window.showInformationMessage(
                `Scan complete: Found ${totalVulns} vulnerabilities across ${results.length} files`
            );
        });
    } catch (error) {
        vscode.window.showErrorMessage(`Scan failed: ${error}`);
    }
}

async function scanFile(document: vscode.TextDocument) {
    try {
        const result = await scanner.scanFile(document.uri.fsPath, document.getText());
        
        // Update diagnostics for this file
        diagnosticsManager.updateFileDiagnostics(document.uri, result.vulnerabilities);
        
        // Update tree view
        treeProvider.updateFileVulnerabilities(document.uri.fsPath, result);
        
        return result;
    } catch (error) {
        console.error(`Failed to scan file ${document.uri.fsPath}:`, error);
    }
}

async function fixVulnerability(vulnerability: any) {
    try {
        const document = await vscode.workspace.openTextDocument(vulnerability.file);
        const editor = await vscode.window.showTextDocument(document);
        
        const fix = await scanner.generateFix(vulnerability);
        if (fix) {
            const edit = new vscode.WorkspaceEdit();
            const range = new vscode.Range(
                vulnerability.line - 1,
                vulnerability.column,
                vulnerability.line - 1,
                vulnerability.column + vulnerability.length
            );
            
            edit.replace(document.uri, range, fix.replacement);
            
            const applied = await vscode.workspace.applyEdit(edit);
            if (applied) {
                vscode.window.showInformationMessage(
                    `Fixed ${vulnerability.type}: ${fix.description}`
                );
                
                // Re-scan the file
                await scanFile(document);
            }
        }
    } catch (error) {
        vscode.window.showErrorMessage(`Failed to fix vulnerability: ${error}`);
    }
}

export function deactivate() {
    diagnosticsManager?.dispose();
}