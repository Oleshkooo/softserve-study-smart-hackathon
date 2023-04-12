import { Schema, model, models } from 'mongoose'

import { DisciplineSchema, type IDiscipline } from './University'

export interface IUser {
    _id: string
    email: string
    password: string
    name: string
    perms: 'admin' | 'teacher' | 'student'
    university_id: string
    speciality_id: string
    disciplines: IDiscipline[]

    isPasswordCorrect: (password: string) => boolean | Promise<boolean>
}

const UserSchema = new Schema<IUser>({
    email: {
        type: String,
        required: true,
    },
    password: {
        type: String,
        required: true,
    },
    name: {
        type: String,
        required: true,
    },
    perms: {
        type: String,
        required: true,
    },
    university_id: {
        type: String,
        required: true,
    },
    speciality_id: {
        type: String,
        required: true,
    },
    disciplines: {
        type: [DisciplineSchema],
        required: true,
    },
})

UserSchema.methods.isPasswordCorrect = async function (password: string) {
    return this.password === password
}

export const UserModel = models.User ?? model('User', UserSchema)
