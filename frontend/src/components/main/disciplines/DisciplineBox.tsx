import {FC, useContext} from 'react';
import classes from './DisciplineBox.module.css'
import { DisciplineObject } from './Disciplines';
import {contextDb} from "@/components/main/Main";

const DisciplineBox: FC<DisciplineObject> = ({data}) => {
    const DataCtx = useContext(contextDb)

    function handleChangeDiscipline() {
        DataCtx?.setSelectedDiscipline(data);
        DataCtx?.setSelectedLab(null);
    }

    return(
        <div className={`${classes.container} ${DataCtx?.selectedDiscipline === data ? classes.selected : ''}`} onClick={handleChangeDiscipline}>
            <p>{data.name}</p>
        </div>
    )
}

export default DisciplineBox;