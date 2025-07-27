import * as vscode from 'vscode';
import { ScanResult, Vulnerability } from '../scanner/vulnerabilityScanner';

export class DiagnosticsManager {
    private diagnosticCollection: vscode.DiagnosticCollection;

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('vulnerabilityScanner');
    }

    updateDiagnostics(results: ScanResult[]): void {
        // Clear all diagnostics first
        this.diagnosticCollection.clear();

        // Add diagnostics for each file
        for (const result of results) {
            this.updateFileDiagnostics(vscode.Uri.file(result.file), result.vulnerabilities);
        }
    }

    updateFileDiagnostics(fileUri: vscode.Uri, vulnerabilities: Vulnerability[]): void {
        const diagnostics: vscode.Diagnostic[] = [];

        for (const vuln of vulnerabilities) {
            const range = new vscode.Range(
                vuln.line - 1,
                vuln.column,
                vuln.line - 1,
                vuln.column + vuln.length
            );

            // Always use Warning for all vulnerabilities (yellow underline only)
            const diagnostic = new vscode.Diagnostic(
                range,
                `${vuln.title}: ${vuln.description}`,
                vscode.DiagnosticSeverity.Warning
            );

            diagnostic.code = vuln.cwe;
            diagnostic.source = `Security Scanner (${vuln.category})`;
            
            // Add related information
            diagnostic.relatedInformation = [
                new vscode.DiagnosticRelatedInformation(
                    new vscode.Location(fileUri, range),
                    `Recommendation: ${vuln.recommendation}`
                )
            ];

            // Add tags
            const tags: vscode.DiagnosticTag[] = [];
            if (vuln.severity === 'low') {
                tags.push(vscode.DiagnosticTag.Unnecessary);
            }
            diagnostic.tags = tags;

            diagnostics.push(diagnostic);
        }

        this.diagnosticCollection.set(fileUri, diagnostics);
    }

    dispose(): void {
        this.diagnosticCollection.dispose();
    }
}