import type { RequestHandler } from 'express'

import { UniversityModel } from '@/Database/models'

export const get: RequestHandler = async (req, res) => {
    try {
        const data = await UniversityModel.find().lean()
        return res.send(data)
    } catch (error) {
        return res.send()
    } finally {
        res.end()
    }
}
