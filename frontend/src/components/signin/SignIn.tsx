import classes from './SignIn.module.css'
import BackButton from '../utils/BackButton'

function SignIn() {
    return (
        <div className={classes.main}>
            <BackButton />
            <h2>Вхід в обліковий запис</h2>
            <form className={classes.form}>
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
                <button
                    type="submit"
                    className={classes.button}>
                    Увійти
                </button>
            </form>
        </div>
    )
}

export default SignIn
