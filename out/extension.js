"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.deactivate = exports.activate = void 0;
const vscode = __importStar(require("vscode"));
const vulnerabilityScanner_1 = require("./scanner/vulnerabilityScanner");
const securityTreeProvider_1 = require("./providers/securityTreeProvider");
const webviewProvider_1 = require("./providers/webviewProvider");
const diagnosticsManager_1 = require("./diagnostics/diagnosticsManager");
let scanner;
let treeProvider;
let webviewProvider;
let diagnosticsManager;
function activate(context) {
    console.log('Vulnerability Scanner Pro is now active!');
    // Initialize components
    scanner = new vulnerabilityScanner_1.VulnerabilityScanner();
    treeProvider = new securityTreeProvider_1.SecurityTreeProvider();
    webviewProvider = new webviewProvider_1.VulnerabilityWebviewProvider(context.extensionUri);
    diagnosticsManager = new diagnosticsManager_1.DiagnosticsManager();
    // Register tree view
    const treeView = vscode.window.createTreeView('vulnerabilityScanner', {
        treeDataProvider: treeProvider,
        showCollapseAll: true
    });
    // Register webview provider
    context.subscriptions.push(vscode.window.registerWebviewViewProvider('vulnerabilityReport', webviewProvider));
    // Register commands
    const scanWorkspaceCommand = vscode.commands.registerCommand('vulnerabilityScanner.scanWorkspace', async () => {
        await scanWorkspace();
    });
    const scanFileCommand = vscode.commands.registerCommand('vulnerabilityScanner.scanFile', async () => {
        const activeEditor = vscode.window.activeTextEditor;
        if (activeEditor) {
            await scanFile(activeEditor.document);
        }
    });
    const fixVulnerabilityCommand = vscode.commands.registerCommand('vulnerabilityScanner.fixVulnerability', async (vulnerability) => {
        await fixVulnerability(vulnerability);
    });
    const showReportCommand = vscode.commands.registerCommand('vulnerabilityScanner.showReport', () => {
        webviewProvider.show();
    });
    // Register event listeners
    const onDidSaveDocument = vscode.workspace.onDidSaveTextDocument(async (document) => {
        const config = vscode.workspace.getConfiguration('vulnerabilityScanner');
        if (config.get('enableAutoScan')) {
            await scanFile(document);
        }
    });
    const onDidOpenTextDocument = vscode.workspace.onDidOpenTextDocument(async (document) => {
        if (document.uri.scheme === 'file') {
            await scanFile(document);
        }
    });
    // Add subscriptions
    context.subscriptions.push(scanWorkspaceCommand, scanFileCommand, fixVulnerabilityCommand, showReportCommand, onDidSaveDocument, onDidOpenTextDocument, treeView);
    // Initial scan on startup
    const config = vscode.workspace.getConfiguration('vulnerabilityScanner');
    if (config.get('scanOnStartup')) {
        setTimeout(() => scanWorkspace(), 2000);
    }
}
exports.activate = activate;
async function scanWorkspace() {
    try {
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "Scanning workspace for vulnerabilities...",
            cancellable: true
        }, async (progress, token) => {
            const workspaceFolders = vscode.workspace.workspaceFolders;
            if (!workspaceFolders)
                return;
            const results = await scanner.scanWorkspace(workspaceFolders[0].uri.fsPath, token);
            // Update diagnostics
            diagnosticsManager.updateDiagnostics(results);
            // Update tree view
            treeProvider.updateVulnerabilities(results);
            // Update webview
            webviewProvider.updateResults(results);
            // Show summary
            const totalVulns = results.reduce((sum, file) => sum + file.vulnerabilities.length, 0);
            vscode.window.showInformationMessage(`Scan complete: Found ${totalVulns} vulnerabilities across ${results.length} files`);
        });
    }
    catch (error) {
        vscode.window.showErrorMessage(`Scan failed: ${error}`);
    }
}
async function scanFile(document) {
    try {
        const result = await scanner.scanFile(document.uri.fsPath, document.getText());
        // Update diagnostics for this file
        diagnosticsManager.updateFileDiagnostics(document.uri, result.vulnerabilities);
        // Update tree view
        treeProvider.updateFileVulnerabilities(document.uri.fsPath, result);
        return result;
    }
    catch (error) {
        console.error(`Failed to scan file ${document.uri.fsPath}:`, error);
    }
}
async function fixVulnerability(vulnerability) {
    try {
        const document = await vscode.workspace.openTextDocument(vulnerability.file);
        const editor = await vscode.window.showTextDocument(document);
        const fix = await scanner.generateFix(vulnerability);
        if (fix) {
            const edit = new vscode.WorkspaceEdit();
            const range = new vscode.Range(vulnerability.line - 1, vulnerability.column, vulnerability.line - 1, vulnerability.column + vulnerability.length);
            edit.replace(document.uri, range, fix.replacement);
            const applied = await vscode.workspace.applyEdit(edit);
            if (applied) {
                vscode.window.showInformationMessage(`Fixed ${vulnerability.type}: ${fix.description}`);
                // Re-scan the file
                await scanFile(document);
            }
        }
    }
    catch (error) {
        vscode.window.showErrorMessage(`Failed to fix vulnerability: ${error}`);
    }
}
function deactivate() {
    diagnosticsManager?.dispose();
}
exports.deactivate = deactivate;
//# sourceMappingURL=extension.js.map