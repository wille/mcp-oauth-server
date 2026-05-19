import path from 'node:path';
import { fileURLToPath } from 'node:url';

import typescript from '@rollup/plugin-typescript';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default {
    input: ['src/index.ts'],
    output: [
        {
            dir: 'dist',
            format: 'cjs',
            preserveModules: true,
            sourcemap: true,
            entryFileNames: '[name].cjs',
        },
        {
            dir: 'dist',
            format: 'module',
            preserveModules: true,
            sourcemap: true,
            entryFileNames: '[name].js',
        },
    ],
    plugins: [
        typescript({
            tsconfig: './tsconfig.json',
            filterRoot: __dirname,
            include: ['src/**/*.ts'],
            exclude: ['src/tests/**', '**/*.test.ts'],
            compilerOptions: {
                rootDir: path.join(__dirname, 'src'),
                declarationDir: path.join(__dirname, 'dist'),
                declaration: true,
            },
        }),
    ],
};
