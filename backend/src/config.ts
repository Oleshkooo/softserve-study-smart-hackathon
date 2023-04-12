import { config } from 'dotenv'

config()

// global
export const PORT = process.env.PORT ?? 4000

// database
// database
export const DB_USER = process.env.DB_USER as string
export const DB_PASS = process.env.DB_PASS as string
export const DB_NAME = process.env.DB_NAME as string
export const DB_CONNSTR = (process.env.DB_CONNSTR as string)
    .replace('<user>', DB_USER)
    .replace('<pass>', DB_PASS)
    .replace('<db>', DB_NAME)
