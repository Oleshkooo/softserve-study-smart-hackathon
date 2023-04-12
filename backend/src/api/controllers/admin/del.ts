import type { RequestHandler } from 'express'

import { ApiError, ApiSuccess, STATUS } from '@/api/responses'
import { UserModel } from '@/Database/models/User'

export const del: RequestHandler = async (req, res) => {
    try {
        const { email } = req.body

        if (email === undefined) {
            const response = new ApiError({
                status: STATUS.BAD_REQUEST,
                message: 'Missing required fields',
            })
            return res.status(response.status).send(response)
        }

        const found = UserModel.findOne({ email })

        if (found === null || found === undefined) {
            const response = new ApiError({
                status: STATUS.BAD_REQUEST,
                message: 'User not found',
            })
            return res.status(response.status).send(response)
        }

        await UserModel.deleteOne({ email })

        const response = new ApiSuccess({
            status: STATUS.OK,
            message: 'User deleted',
        })
        return res.status(response.status).send(response)
    } catch (error) {
        const response = ApiError.internalServerError(error)
        return res.status(response.status).send(response)
    } finally {
        res.end()
    }
}
