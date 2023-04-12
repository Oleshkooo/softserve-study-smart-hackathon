import Disciplines from './disciplines/Disciplines'
import classes from './Main.module.css'
import { createContext, useEffect, useState } from 'react'
import Discipline from '@/components/main/discipline/Discipline'
import Review from '@/components/main/review/Review'
import Students from './students/Students'

export interface Labs extends JSX.IntrinsicAttributes {
    name: string
    rating: number
    msg: string
    points: number
}

export interface IDiscipline extends JSX.IntrinsicAttributes {
    name: string
    teacher: string
    teacherEmail: string
    labs: Labs[]
}

export interface DisciplineObject extends JSX.IntrinsicAttributes {
    [index: number]: {
        name: string
        teacher: string
        teacherEmail: string
        labs: Labs[]
    }
}

export interface IUser extends JSX.IntrinsicAttributes {
    email: string
    password: string
    perms: string
    name: string
    university_id: string
    speciality_id: string
    disciplines: DisciplineObject[]
}

export interface ContextObject extends JSX.IntrinsicAttributes {
    data: IUser
    selectedDiscipline: number
    setSelectedDiscipline: (name: string) => void
    selectedLab: Labs
    setSelectedLab: (lab: Labs) => void
    students: IUser[]
    setStudents: (users: IUser[]) => void
    selectedStudent: IUser
    setSelectedStudent: (users: IUser) => void,
    teacherRating: number
    setTeacherRating: (rating: number) => void
    teacherHover: number
    setTeacherHover: (rating: number) => void
    studentRating: number
    setStudentRating: (rating: number) => void
    studentHover: number
    setStudentHover: (rating: number) => void
}

let contextDb = createContext<ContextObject | null>(null)

const dummy_disciplines: IUser = {
    email: 'svobodamv@lpnu.ua',
    password: '08.06.2004',
    perms: 'student',
    name: 'Свобода Максим Вікторович',
    university_id: '97',
    speciality_id: '081',
    disciplines: [
        {
            name: 'Фізична культура',
            teacher: 'Худенко Катерина Олегівна',
            teacherEmail: 'hudenkoko@ldubzh.ua',
            labs: [
                {
                    name: 'Лабораторна робота №1',
                    rating: 0,
                    msg: '',
                },
                {
                    name: 'Лабораторна робота №2',
                    rating: 0,
                    msg: '',
                },
                {
                    name: 'Лабораторна робота №3',
                    rating: 0,
                    msg: '',
                },
                {
                    name: 'Лабораторна робота №4',
                    rating: 0,
                    msg: '',
                },
            ],
        },
        {
            name: 'Мистецтво',
            teacher: 'Мірошниченко Валерія Максимівна',
            teacherEmail: 'miroshnychenkovm@gmail.com',
            labs: [
                {
                    name: 'Лабораторна робота №1',
                    rating: 0,
                    msg: '',
                },
                {
                    name: 'Лабораторна робота №2',
                    rating: 0,
                    msg: '',
                },
                {
                    name: 'Лабораторна робота №3',
                    rating: 0,
                    msg: '',
                },
            ],
        },
        {
            name: 'Теологія',
            teacher: 'Кравченко Тарас Іванович',
            teacherEmail: 'kravchenkoti@lnu.ua',
            labs: [
                {
                    name: 'Лабораторна робота №1',
                    rating: 5,
                    msg: '',
                    points: 4
                },
                {
                    name: 'Лабораторна робота №2',
                    rating: 0,
                    msg: '',
                },
                {
                    name: 'Лабораторна робота №3',
                    rating: 0,
                    msg: '',
                },
                {
                    name: 'Лабораторна робота №4',
                    rating: 0,
                    msg: '',
                },
                {
                    name: 'Лабораторна робота №5',
                    rating: 0,
                    msg: '',
                },
            ],
        },
        {
            name: 'Англійська мова',
            teacher: 'Руденко Даниїл Романович',
            teacherEmail: 'rudenkodr@lnam.ua',
            labs: [
                {
                    name: 'Лабораторна робота №1',
                    rating: 0,
                    msg: '',
                },
                {
                    name: 'Лабораторна робота №2',
                    rating: 0,
                    msg: '',
                },
                {
                    name: 'Лабораторна робота №3',
                    rating: 0,
                    msg: '',
                },
                {
                    name: 'Лабораторна робота №4',
                    rating: 0,
                    msg: '',
                },
            ],
        },
    ],
}

const dummy_teacher: IUser = {
    email: 'miroshnychenkovm@gmail.com',
    password: '09.02.1965',
    perms: 'teacher',
    name: 'Мірошниченко Валерія Максимівна',
    university_id: '',
    speciality_id: '',
    disciplines: [],
}

const dummy_students: IUser[] = [
    {
        email: 'svobodamv@lpnu.ua',
        password: '08.06.2004',
        perms: 'student',
        name: 'Свобода Максим Вікторович',
        university_id: '97',
        speciality_id: '081',
        disciplines: [
            {
                name: 'Фізична культура',
                teacher: 'Худенко Катерина Олегівна',
                teacherEmail: 'hudenkoko@ldubzh.ua',
                labs: [
                    {
                        name: 'Лабораторна робота №1',
                        rating: 0,
                        msg: '',
                    },
                    {
                        name: 'Лабораторна робота №2',
                        rating: 0,
                        msg: '',
                    },
                    {
                        name: 'Лабораторна робота №3',
                        rating: 0,
                        msg: '',
                    },
                    {
                        name: 'Лабораторна робота №4',
                        rating: 0,
                        msg: '',
                    },
                ],
            },
            {
                name: 'Мистецтво',
                teacher: 'Мірошниченко Валерія Максимівна',
                teacherEmail: 'miroshnychenkovm@gmail.com',
                labs: [
                    {
                        name: 'Лабораторна робота №1',
                        rating: 4,
                        msg: 'Aboba',
                        points: 3
                    },
                    {
                        name: 'Лабораторна робота №2',
                        rating: 0,
                        msg: '',
                        points: 0
                    },
                    {
                        name: 'Лабораторна робота №3',
                        rating: 0,
                        msg: '',
                        points: 0
                    },
                ],
            },
            {
                name: 'Теологія',
                teacher: 'Кравченко Тарас Іванович',
                teacherEmail: 'kravchenkoti@lnu.ua',
                labs: [
                    {
                        name: 'Лабораторна робота №1',
                        rating: 4,
                        msg: '',
                        points: 3
                    },
                    {
                        name: 'Лабораторна робота №2',
                        rating: 0,
                        msg: '',
                    },
                    {
                        name: 'Лабораторна робота №3',
                        rating: 0,
                        msg: '',
                    },
                    {
                        name: 'Лабораторна робота №4',
                        rating: 0,
                        msg: '',
                    },
                    {
                        name: 'Лабораторна робота №5',
                        rating: 0,
                        msg: '',
                    },
                ],
            },
            {
                name: 'Англійська мова',
                teacher: 'Руденко Даниїл Романович',
                teacherEmail: 'rudenkodr@lnam.ua',
                labs: [
                    {
                        name: 'Лабораторна робота №1',
                        rating: 0,
                        msg: '',
                    },
                    {
                        name: 'Лабораторна робота №2',
                        rating: 0,
                        msg: '',
                    },
                    {
                        name: 'Лабораторна робота №3',
                        rating: 0,
                        msg: '',
                    },
                    {
                        name: 'Лабораторна робота №4',
                        rating: 0,
                        msg: '',
                    },
                ],
            },
        ],
    },
]

function Main() {
    const [selectedDiscipline, setSelectedDiscipline] = useState<IDiscipline>()
    const [selectedLab, setSelectedLab] = useState<Labs>()
    const [students, setStudents] = useState<IUser[]>()
    const [selectedStudent, setSelectedStudent] = useState<IUser[]>()
    const [teacherRating, setTeacherRating] = useState<number>(0)
    const [teacherHover, setTeacherHover] = useState<number>(0)
    const [studentRating, setStudentRating] = useState<number>(0)
    const [studentHover, setStudentHover] = useState<number>(0)

    const CtxData: ContextObject = {
        data: dummy_disciplines,
        selectedDiscipline: selectedDiscipline,
        setSelectedDiscipline: setSelectedDiscipline,
        selectedLab: selectedLab,
        setSelectedLab: setSelectedLab,
        students: dummy_students,
        setStudents: setStudents,
        selectedStudent: selectedStudent,
        setSelectedStudent: setSelectedStudent,
        teacherRating: teacherRating,
        setTeacherRating: setTeacherRating,
        teacherHover: teacherHover,
        setTeacherHover: setTeacherHover,
        studentRating: studentRating,
        setStudentRating: setStudentRating,
        studentHover: studentHover,
        setStudentHover: setStudentHover
    }

    return (
        <contextDb.Provider value={CtxData}>
            <div className={classes.main}>
                <h1>Вітаємо, {CtxData.data.name.split(' ')[1]}!</h1>
                <article>
                    {CtxData.data.perms === 'student' ? <Disciplines /> : <Students />}
                    {CtxData.selectedDiscipline ? <Discipline /> : <></>}
                    {CtxData.selectedLab ? <Review /> : <></>}
                </article>
            </div>
        </contextDb.Provider>
    )
}

export default Main

export { contextDb }
