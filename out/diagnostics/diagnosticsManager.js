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
exports.DiagnosticsManager = void 0;
const vscode = __importStar(require("vscode"));
class DiagnosticsManager {
    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('vulnerabilityScanner');
    }
    updateDiagnostics(results) {
        // Clear all diagnostics first
        this.diagnosticCollection.clear();
        // Add diagnostics for each file
        for (const result of results) {
            this.updateFileDiagnostics(vscode.Uri.file(result.file), result.vulnerabilities);
        }
    }
    updateFileDiagnostics(fileUri, vulnerabilities) {
        const diagnostics = [];
        for (const vuln of vulnerabilities) {
            const range = new vscode.Range(vuln.line - 1, vuln.column, vuln.line - 1, vuln.column + vuln.length);
            // Always use Warning for all vulnerabilities (yellow underline only)
            const diagnostic = new vscode.Diagnostic(range, `${vuln.title}: ${vuln.description}`, vscode.DiagnosticSeverity.Warning);
            diagnostic.code = vuln.cwe;
            diagnostic.source = `Security Scanner (${vuln.category})`;
            // Add related information
            diagnostic.relatedInformation = [
                new vscode.DiagnosticRelatedInformation(new vscode.Location(fileUri, range), `Recommendation: ${vuln.recommendation}`)
            ];
            // Add tags
            const tags = [];
            if (vuln.severity === 'low') {
                tags.push(vscode.DiagnosticTag.Unnecessary);
            }
            diagnostic.tags = tags;
            diagnostics.push(diagnostic);
        }
        this.diagnosticCollection.set(fileUri, diagnostics);
    }
    dispose() {
        this.diagnosticCollection.dispose();
    }
}
exports.DiagnosticsManager = DiagnosticsManager;
//# sourceMappingURL=diagnosticsManager.js.map