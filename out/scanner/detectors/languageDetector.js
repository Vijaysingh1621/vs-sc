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
exports.LanguageDetector = void 0;
const path = __importStar(require("path"));
class LanguageDetector {
    detectLanguage(filePath, content) {
        const extension = path.extname(filePath).toLowerCase();
        // Extension-based detection
        const extensionMap = {
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.vue': 'vue',
            '.svelte': 'svelte',
            '.py': 'python',
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.cxx': 'cpp',
            '.cs': 'csharp',
            '.php': 'php',
            '.rb': 'ruby',
            '.go': 'go',
            '.rs': 'rust',
            '.kt': 'kotlin',
            '.swift': 'swift',
            '.scala': 'scala',
            '.sql': 'sql',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.json': 'json',
            '.xml': 'xml',
            '.html': 'html',
            '.htm': 'html',
            '.css': 'css',
            '.scss': 'scss',
            '.sass': 'sass'
        };
        if (extensionMap[extension]) {
            return extensionMap[extension];
        }
        // Content-based detection fallback
        if (content.includes('<?php'))
            return 'php';
        if (content.includes('#!/usr/bin/env python') || content.includes('#!/usr/bin/python'))
            return 'python';
        if (content.includes('#!/bin/bash') || content.includes('#!/bin/sh'))
            return 'bash';
        if (content.includes('package main') && content.includes('func main()'))
            return 'go';
        if (content.includes('fn main()'))
            return 'rust';
        if (content.includes('public static void main'))
            return 'java';
        if (content.includes('using System;'))
            return 'csharp';
        // JavaScript/TypeScript detection
        if (content.includes('import ') || content.includes('export ') || content.includes('require(')) {
            if (content.includes(': ') && (content.includes('interface ') || content.includes('type '))) {
                return 'typescript';
            }
            return 'javascript';
        }
        return 'unknown';
    }
    getSupportedLanguages() {
        return [
            'javascript', 'typescript', 'python', 'java', 'c', 'cpp', 'csharp',
            'php', 'ruby', 'go', 'rust', 'kotlin', 'swift', 'scala',
            'sql', 'yaml', 'json', 'xml', 'html', 'css', 'scss', 'sass',
            'vue', 'svelte', 'bash'
        ];
    }
    isSupported(language) {
        return this.getSupportedLanguages().includes(language);
    }
}
exports.LanguageDetector = LanguageDetector;
//# sourceMappingURL=languageDetector.js.map