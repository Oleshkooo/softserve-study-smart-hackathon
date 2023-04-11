// import terser from '@rollup/plugin-terser'
import alias from '@rollup/plugin-alias'
import commonjs from '@rollup/plugin-commonjs'
import json from '@rollup/plugin-json'
import resolve from '@rollup/plugin-node-resolve'
import typescript from '@rollup/plugin-typescript'
import copy from 'rollup-plugin-copy'
import del from 'rollup-plugin-delete'

const isProd = process.env.NODE_ENV === 'production'
const SRC_DIR = 'src'
const BUILD_DIR = 'build'
const STATIC_DIR = 'static'

const external = isProd
    ? []
    : ['path', 'body-parser', 'compression', 'cors', 'dotenv', 'express', 'mongoose']

const plugins = [
    del({
        targets: `./${BUILD_DIR}/*`,
    }),
    typescript({
        tsconfig: './tsconfig.json',
    }),
    alias({
        entries: [{ find: '@', replacement: `./${SRC_DIR}` }],
    }),
    copy({
        targets: [
            { src: `./${SRC_DIR}/${STATIC_DIR}/*`, dest: `./${BUILD_DIR}/${STATIC_DIR}` },
            { src: `./.env`, dest: `./${BUILD_DIR}` },
        ],
    }),
    resolve({
        moduleDirectories: ['node_modules'],
        preferBuiltins: true,
    }),
    commonjs(),
    json(),
    // terser(),
]

export default {
    plugins,
    external,
    input: `./${SRC_DIR}/index.ts`,
    output: {
        dir: `./${BUILD_DIR}`,
        format: 'cjs',
        exports: 'none',
        strict: true,
        sourcemap: isProd ? false : 'inline',
    },
}
