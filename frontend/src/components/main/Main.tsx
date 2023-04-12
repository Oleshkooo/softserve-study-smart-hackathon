import Disciplines from './disciplines/Disciplines'
import classes from './Main.module.css'
import { useContext, useEffect } from 'react'
import Discipline from '@/components/main/discipline/Discipline'
import Review from '@/components/main/review/Review'
import Students from './students/Students'
import { contextDb } from '@/App'
import { useNavigate } from 'react-router-dom'

function Main() {
    const CtxData = useContext(contextDb)
    const navigator = useNavigate()

    useEffect(() => {
        if (!CtxData?.data) navigator('/start')
    }, [])

    return (
        <div className={classes.main}>
            {CtxData?.data === undefined ? (
                <></>
            ) : (
                <>
                    <h1>Вітаємо, {CtxData?.data.name.split(' ')[1]}!</h1>
                    <article>
                        {CtxData?.data.perms === 'student' ? <Disciplines /> : <Students />}
                        {CtxData?.selectedDiscipline ? <Discipline /> : <></>}
                        {CtxData?.selectedLab ? <Review /> : <></>}
                    </article>
                </>
            )}
        </div>
    )
}

export default Main

export { contextDb }
