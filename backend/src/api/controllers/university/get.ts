import type { RequestHandler } from 'express'

import { ApiError, ApiSuccess, STATUS } from '@/api/responses'
import { UniversityModel, type IUniversity } from '@/Database/models'

export const get: RequestHandler = async (req, res) => {
    try {
        const { id, abbr } = req.body

        const data = await (async () => {
            if (id !== undefined) {
                return await UniversityModel.find({ id }).lean()
            }
            if (abbr !== undefined) {
                return await UniversityModel.find({ abbr }).lean()
            }
            return await UniversityModel.find().lean()
        })()

        const response = new ApiSuccess<IUniversity[]>({
            status: STATUS.OK,
            message: 'Success',
            data,
        })
        return res.status(response.status).send(response)
    } catch (error) {
        const response = ApiError.internalServerError(error)
        return res.status(response.status).send(response)
    } finally {
        res.end()
    }
}
