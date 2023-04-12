import { useContext } from 'react'
import { contextDb } from '../Main'
import classes from './Students.module.css'
import StudentBox from './StudentBox'

function Students() {

    const DataCtx = useContext(contextDb)

    return(
        <div className={classes.container}>
            <h2>Студенти</h2>
            {DataCtx?.students.map(item => (
                <StudentBox data={item} />
            ))}
        </div>
    )
}

export default Students
