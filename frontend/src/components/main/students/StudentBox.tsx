import { FC, useContext } from "react";
import { IUser, contextDb } from "../Main";
import classes from './StudentBox.module.css'

const StudentBox: FC<IUser> = ({data}) => { 
    const DataCtx = useContext(contextDb)

    function handleChangeStudent() {
        DataCtx?.setSelectedStudent(data)
        DataCtx?.setSelectedDiscipline(data.disciplines.find(e => e.teacherEmail === DataCtx.data.email))
    }

    return(
        <div className={`${classes.container} ${DataCtx?.selectedStudent === data 
        ? classes.selected : ''}`} onClick={handleChangeStudent}>
            <p>{data.name}</p>
        </div>
    )
}

export default StudentBox;