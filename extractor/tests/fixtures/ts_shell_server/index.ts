import { execSync, spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import axios from 'axios';

export function runCommand(cmd: string): string {
    return execSync(cmd, { encoding: 'utf-8' });
}

export function readFile(filePath: string): string {
    return fs.readFileSync(filePath, 'utf-8');
}

export function fetchUrl(url: string) {
    return axios.get(url);
}

export function executeScript(scriptPath: string) {
    return spawn('bash', [scriptPath]);
}
