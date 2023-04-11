import { FC } from 'react';
import classes from './DisciplineBox.module.css'
import { DisciplineObject } from './Disciplines';

const DisciplineBox: FC<DisciplineObject> = ({data}) => {
    return(
        <div className={classes.container}>
            <h3>{data.name}</h3>
        </div>
    )
}

export default DisciplineBox;