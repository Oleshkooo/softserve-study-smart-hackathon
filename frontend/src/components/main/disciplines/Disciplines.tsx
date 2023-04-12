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

function Disciplines() {
    const DiscCtx = useContext(contextDb)

    return (
        <div className={classes.container}>
            <h2>Дисципліни</h2>
            {DiscCtx?.data.disciplines.map(item => (
                <DisciplineBox data={item} />
            ))}
        </div>
    )
}

export default Disciplines;
