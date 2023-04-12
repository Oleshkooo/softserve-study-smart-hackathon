import { Schema, model, models } from 'mongoose'

interface ILab {
    name: string
    rating: number
    message: string
}

export interface IDiscipline {
    name: string
    teacher: string
    teacherEmail: string
    labs: ILab[]
}

interface ISpecialitie {
    id: string
    name: string
    disciplines: IDiscipline[]
}

export interface IUniversity {
    _id: number
    id: string
    name: string
    abbr: string
    specialities: ISpecialitie[]
}

const LabSchema = new Schema<ILab>({
    name: {
        type: String,
        required: true,
    },
    rating: {
        type: Number,
        required: true,
    },
    message: {
        type: String,
        required: true,
    },
})

export const DisciplineSchema = new Schema<IDiscipline>({
    name: {
        type: String,
        required: true,
    },
    teacher: {
        type: String,
        required: true,
    },
    teacherEmail: {
        type: String,
        required: true,
    },
    labs: {
        type: [LabSchema],
        required: true,
    },
})

const SpecialitieSchema = new Schema<ISpecialitie>({
    id: {
        type: String,
        required: true,
    },
    name: {
        type: String,
        required: true,
    },
    disciplines: {
        type: [DisciplineSchema],
        required: true,
    },
})

const UniversitySchema = new Schema<IUniversity>({
    _id: {
        type: Number,
        required: true,
    },
    id: {
        type: String,
        required: true,
    },
    name: {
        type: String,
        required: true,
    },
    abbr: {
        type: String,
        required: true,
    },
    specialities: {
        type: [SpecialitieSchema],
        required: true,
    },
})

export const UniversityModel = models.University ?? model('University', UniversitySchema)
