import type { RequestHandler } from 'express'

import { ApiError, ApiSuccess, STATUS } from '@/api/responses'
import { UserModel, type IUser } from '@/Database/models/User'

export const put: RequestHandler = async (req, res) => {
    try {
        const { studentEmail, teacherEmail, labName, rating, message, points } = req.body

        if (
            studentEmail === undefined ||
            teacherEmail === undefined ||
            labName === undefined ||
            rating === undefined ||
            message === undefined ||
            points === undefined
        ) {
            const response = new ApiError({
                status: STATUS.BAD_REQUEST,
                message: 'Missing required fields',
            })

            return res.status(response.status).send(response)
        }

        const updatedStudent = await UserModel.findOneAndUpdate(
            {
                email: studentEmail,
                'disciplines.teacherEmail': teacherEmail,
                'disciplines.labs.name': labName,
            },
            {
                $set: {
                    'disciplines.$[discipline].labs.$[lab].rating': rating,
                    'disciplines.$[discipline].labs.$[lab].message': message,
                    'disciplines.$[discipline].labs.$[lab].points': points,
                },
            },
            {
                arrayFilters: [
                    { 'discipline.teacherEmail': teacherEmail },
                    { 'lab.name': labName },
                ],
                new: true,
            },
        )

        const response = new ApiSuccess<IUser[]>({
            status: STATUS.OK,
            message: 'Success',
            data: updatedStudent,
        })
        return res.status(response.status).send(response)
    } catch (error) {
        const response = ApiError.internalServerError(error)
        return res.status(response.status).send(response)
    } finally {
        res.end()
    }
}
