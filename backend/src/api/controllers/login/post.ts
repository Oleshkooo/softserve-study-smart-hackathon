import type { RequestHandler } from 'express'

import { ApiError, ApiSuccess, STATUS } from '@/api/responses'
import { UserModel } from '@/Database/models/User'

export const post: RequestHandler = async (req, res) => {
    try {
        const { email, password } = req.body

        if (email === undefined || password === undefined) {
            const response = new ApiError({
                status: STATUS.BAD_REQUEST,
                message: 'Missing required fields',
            })
            return res.status(response.status).send(response)
        }

        const user = await UserModel.findOne({ email })
        const isPasswordCorrect: boolean = await user.isPasswordCorrect(password)

        if (!isPasswordCorrect) {
            const response = new ApiError({
                status: STATUS.UNAUTHORIZED,
                message: 'Email or password is incorrect',
            })
            return res.status(response.status).send(response)
        }

        const response = new ApiSuccess({
            status: STATUS.OK,
            message: 'Success',
            data: user,
        })
        return res.status(response.status).send(response)
    } catch (error) {
        const response = ApiError.internalServerError(error)
        return res.status(response.status).send(response)
    } finally {
        res.end()
    }
}
