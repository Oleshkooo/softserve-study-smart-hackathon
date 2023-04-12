import {FC, useContext} from "react";
import {contextDb} from "@/components/main/Main";
import {Labs} from "@/App";
import dClasses from './Discipline.module.css'

const LabBox: FC<Labs> = (data) => {
    const DataCtx = useContext(contextDb)

    function handleChangeLab() {
        DataCtx?.setSelectedLab(data.data)
        DataCtx?.setTeacherRating(data.data.points)
        DataCtx?.setStudentRating(data.data.rating)
        DataCtx?.setStudentHover(0);
        DataCtx?.setTeacherHover(0)
    }

    return(
        <div className={`${dClasses.lab} ${DataCtx?.selectedLab === data.data ? dClasses.selected : ''}`} onClick={handleChangeLab}>
            <p>{data.data.name}</p>
        </div>
    )
}

export default LabBox;