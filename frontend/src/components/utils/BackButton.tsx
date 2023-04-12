import arrow from '@/assets/img/arrow.svg'
import classes from './BackButton.module.css'
import { useNavigate } from 'react-router-dom'

function BackButton() {
    const navigator = useNavigate();
    
    function handleRedirect() {
        navigator('/start');
    }

    return (
        <div className={classes.back} onClick={handleRedirect}>
            <img src={arrow} />
            <p>Назад</p>
        </div>
    )
}

export default BackButton
