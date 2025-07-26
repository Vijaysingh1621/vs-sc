import * as path from 'path';

export class LanguageDetector {
    detectLanguage(filePath: string, content: string): string {
        const extension = path.extname(filePath).toLowerCase();
        
        // Extension-based detection
        const extensionMap: { [key: string]: string } = {
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
        if (content.includes('<?php')) return 'php';
        if (content.includes('#!/usr/bin/env python') || content.includes('#!/usr/bin/python')) return 'python';
        if (content.includes('#!/bin/bash') || content.includes('#!/bin/sh')) return 'bash';
        if (content.includes('package main') && content.includes('func main()')) return 'go';
        if (content.includes('fn main()')) return 'rust';
        if (content.includes('public static void main')) return 'java';
        if (content.includes('using System;')) return 'csharp';

        // JavaScript/TypeScript detection
        if (content.includes('import ') || content.includes('export ') || content.includes('require(')) {
            if (content.includes(': ') && (content.includes('interface ') || content.includes('type '))) {
                return 'typescript';
            }
            return 'javascript';
        }

        return 'unknown';
    }

    getSupportedLanguages(): string[] {
        return [
            'javascript', 'typescript', 'python', 'java', 'c', 'cpp', 'csharp',
            'php', 'ruby', 'go', 'rust', 'kotlin', 'swift', 'scala',
            'sql', 'yaml', 'json', 'xml', 'html', 'css', 'scss', 'sass',
            'vue', 'svelte', 'bash'
        ];
    }

    isSupported(language: string): boolean {
        return this.getSupportedLanguages().includes(language);
    }
}