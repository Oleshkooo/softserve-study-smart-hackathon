import type { RequestHandler } from 'express'

import { UniversityModel, type IUniversity } from '@/Database/models'
import { ApiError, ApiSuccess, STATUS } from '@/api/responses'

export const get: RequestHandler = async (req, res) => {
    try {
        const universities = await UniversityModel.find().lean()
        const data = universities.find((item: IUniversity) => item.abbr === 'LPNU')
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
