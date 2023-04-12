import { useContext } from 'react'
import { contextDb } from '@/components/main/Main'
import classes from './Discipline.module.css'
import LabBox from '@/components/main/discipline/LabBox'

function Discipline() {
    const DataCtx = useContext(contextDb)

    return (
        <div className={classes.container}>
            <h3>{DataCtx?.selectedDiscipline.name}</h3>
                {DataCtx?.data.perms === 'student' ? 
                    <section>
                        <p>Викладач: {DataCtx?.selectedDiscipline.teacher}</p>
                        <p>E-mail: {DataCtx?.selectedDiscipline.teacherEmail}</p>
                    </section>
                 : 
                    <></>
                }
            <span className={classes.labs}>
                {DataCtx?.selectedDiscipline.labs.map(item => (
                    <LabBox data={item} />
                ))}
            </span>
        </div>
    )
}

export default Discipline
