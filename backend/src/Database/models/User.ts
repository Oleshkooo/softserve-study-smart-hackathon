import { Schema, model, models } from 'mongoose'

import { DisciplineSchema, type IDiscipline } from './University'

export interface IUser {
    _id: string
    perms: 'admin' | 'teacher' | 'student'
    email?: string
    password?: string
    name?: string
    university_id?: string
    speciality_id?: string
    disciplines?: IDiscipline[]

    isPasswordCorrect: (password: string) => boolean | Promise<boolean>
}

const UserSchema = new Schema<IUser>({
    email: {
        type: String,
        required: false,
        default: '',
    },
    password: {
        type: String,
        required: false,
        default: '',
    },
    name: {
        type: String,
        required: false,
        default: '',
    },
    perms: {
        type: String,
        required: true,
    },
    university_id: {
        type: String,
        required: false,
        default: '',
    },
    speciality_id: {
        type: String,
        required: false,
        default: '',
    },
    disciplines: {
        type: [DisciplineSchema],
        required: false,
        default: [],
    },
})

UserSchema.methods.isPasswordCorrect = async function (password: string) {
    return this.password === password
}

export const UserModel = models.User ?? model('User', UserSchema)
