import Disciplines from './disciplines/Disciplines'
import classes from './Main.module.css'
import { useContext } from 'react';

function Main() {
    

    return(
        <div className={classes.main}>
            <Disciplines />
        </div>
    )
}

export default Main;