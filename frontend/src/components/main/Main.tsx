import Disciplines from './disciplines/Disciplines'
import classes from './Main.module.css'
import {createContext, useEffect, useState} from "react";
import Discipline from "@/components/main/discipline/Discipline";
import Review from "@/components/main/review/Review";

export interface Labs extends JSX.IntrinsicAttributes {
    name: string
    rating: number
    msg: string
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

export interface ContextObject extends JSX.IntrinsicAttributes {
    data: DisciplineObject[]
    selectedDiscipline: number
    setSelectedDiscipline: (string) => void,
    selectedLab: Labs,
    setSelectedLab: (Labs) => void
}

let contextDb = createContext<ContextObject | null>(null);


const dummy_disciplines: DisciplineObject = [
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

function Main() {
    const [selectedDiscipline, setSelectedDiscipline] = useState<IDiscipline>();
    const [selectedLab, setSelectedLab] = useState<Labs>();

    const CtxData: ContextObject = {
        data: dummy_disciplines,
        selectedDiscipline: selectedDiscipline,
        setSelectedDiscipline: setSelectedDiscipline,
        selectedLab: selectedLab,
        setSelectedLab: setSelectedLab
    }

    return (
        <contextDb.Provider value={CtxData}>
            <div className={classes.main}>
                <Disciplines/>
                {CtxData.selectedDiscipline ? <Discipline/> : <></>}
                {CtxData.selectedLab ? <Review /> : <></>}
            </div>
        </contextDb.Provider>
    )
}

export default Main;

export {contextDb};