import { connect, connection, set } from 'mongoose'

import { DB_CONNSTR, DB_NAME } from '@/config'

type IsConnected = () => boolean
type Connect = () => IsConnected | Promise<IsConnected>
interface IDatabase {
    isConnected: IsConnected
    connect: Connect
}

set('strictQuery', false)

export class Database implements IDatabase {
    private static instance: Database | null = null

    constructor() {
        if (Database.instance === null) Database.instance = this
        return Database.instance
    }

    public isConnected: IsConnected = () => connection.readyState === 1

    public connect: Connect = async () => {
        const defaultReturn = this.isConnected

        if (this.isConnected()) return defaultReturn

        console.log('[DB] Connecting...')
        try {
            await connect(DB_CONNSTR)
            console.log(`[DB] Connected to "${DB_NAME}"`)
        } catch (error) {
            console.error('[DB] Connection error')
            console.error(error)
        }

        return defaultReturn
    }
}
