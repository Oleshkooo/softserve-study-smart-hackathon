import type { RequestHandler } from 'express'

import { ApiError, STATUS } from '@/api/responses'

export const post: RequestHandler = async (req, res) => {
    try {
        const { email, password } = req.body

        if (email === undefined || password === undefined) {
            const response = new ApiError({
                status: STATUS.BAD_REQUEST,
                message: 'Email or password is missing',
            })
            return res.status(response.status).send(response)
        }

        // const
    } catch (error) {
        const response = ApiError.internalServerError(error)
        return res.status(response.status).send(response)
    } finally {
        res.end()
    }
}
