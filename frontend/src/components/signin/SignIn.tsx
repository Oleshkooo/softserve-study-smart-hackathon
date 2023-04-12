import classes from './SignIn.module.css'
import BackButton from '../utils/BackButton'
import { logInUser } from '../API'
import { useContext, useState } from 'react'
import { contextDb } from '../main/Main'
import { useNavigate } from 'react-router-dom'

function SignIn() {
    const CtxData = useContext(contextDb);
    const navigator = useNavigate();
    const [errMsg, setErrMsg] = useState<string>('');

    function handleSubmit(e) {
        e.preventDefault()

        const data = {
            email: e.target.email.value,
            password: e.target.password.value,
        }

        logInUser(data).then(res => {
            CtxData?.setData(res.data.data)
            setErrMsg('');
            navigator('/');
        })
        .catch(err => {
            setErrMsg('Неірна пошта або пароль')
        })
    }

    return (
        <div className={classes.main}>
            <BackButton />
            <h2>Вхід в обліковий запис</h2>
            <form className={classes.form} onSubmit={handleSubmit}>
                <div className={classes.fields}>
                    <input
                        type={'email'}
                        id={'email'}
                        key={'email'}
                        placeholder={'E-mail'}
                        required
                    />
                    <input
                        type={'password'}
                        id={'password'}
                        key={'password'}
                        placeholder={'Пароль'}
                        required
                    />
                </div>
                {errMsg ? <p>{errMsg}</p> : <></>}
                <button type="submit" className={classes.button}>
                    Увійти
                </button>
            </form>
        </div>
    )
}

export default SignIn
