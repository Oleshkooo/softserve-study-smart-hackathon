import type { RequestHandler } from 'express'

import { ApiError, STATUS } from '@/api/responses'
import { UserModel } from '@/Database/models/User'

export const post: RequestHandler = async (req, res) => {
    try {
        const { email, password, name, universityId, specialityId, perms } = req.body

        if (
            email === undefined ||
            password === undefined ||
            name === undefined ||
            universityId === undefined ||
            specialityId === undefined ||
            perms === undefined
        ) {
            const response = new ApiError({
                status: STATUS.BAD_REQUEST,
                message: 'Missing required fields',
            })
            return res.status(response.status).send(response)
        }

        const user = await UserModel.create({
            email,
            password,
            name,
            perms,
            university_id: universityId,
            speciality_id: specialityId,
        })
        const validationError = user.validateSync()

        if (validationError !== undefined) {
            const response = new ApiError({
                status: STATUS.BAD_REQUEST,
                message: 'Validation error',
            })
            return res.status(response.status).send(response)
        }

        await user.save()

        const response = {
            status: STATUS.OK,
            message: 'User created',
            data: user,
        }
        return res.status(response.status).send(response)
    } catch (error) {
        const response = ApiError.internalServerError(error)
        return res.status(response.status).send(response)
    } finally {
        res.end()
    }
}
