import {useContext, useEffect} from 'react'
import DisciplineBox from './DisciplineBox'
import classes from './Disciplines.module.css'
import {contextDb} from "@/components/main/Main";

interface Labs extends JSX.IntrinsicAttributes {
    name: string
    rating: number
    msg: string
}

export interface DisciplineObject extends JSX.IntrinsicAttributes {
    data: {
        name: string
        teacher: string
        teacherEmail: string
        labs: Labs[]
    }
}

const dummy_disciplines = [
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
]


function Disciplines() {
    const DiscCtx = useContext(contextDb)

    return (
        <div className={classes.container}>
            <h2>Дисципліни</h2>
            {DiscCtx?.data.map(item => (
                <DisciplineBox data={item} />
            ))}
        </div>
    )
}

export default Disciplines;
