import type { RequestHandler } from 'express'

import { ApiError, ApiSuccess, STATUS } from '@/api/responses'
import { UserModel, type IUser } from '@/Database/models/User'

export const get: RequestHandler = async (req, res) => {
    try {
        const { teacherEmail } = req.body

        if (teacherEmail === undefined) {
            const response = new ApiError({
                status: STATUS.BAD_REQUEST,
                message: 'Missing required fields',
            })
            return res.status(response.status).send(response)
        }

        const students = await UserModel.find({
            disciplines: { $elemMatch: { teacherEmail } },
        }).lean()

        const response = new ApiSuccess<IUser[]>({
            status: STATUS.OK,
            message: 'Success',
            data: students,
        })
        return res.status(response.status).send(response)
    } catch (error) {
        const response = ApiError.internalServerError(error)
        return res.status(response.status).send(response)
    } finally {
        res.end()
    }
}
