import { server } from './server'

import { Database } from '@/Database'
import { mainListen } from '@/api/controllers'
import { PORT } from '@/config'

const start = async () => {
    const database = new Database()

    void server.listen(PORT, mainListen)
    void database.connect()
}

void start()
