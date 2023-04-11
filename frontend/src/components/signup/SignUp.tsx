import classes from './SignUp.module.css'

function SignUp() {
    return (
        <div className={classes.main}>
            <h2>Реєстрація облікового запису</h2>
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
                    <input
                        type={'text'}
                        id={'surname'}
                        key={'surname'}
                        placeholder={'Прізвище'}
                        required
                    />
                    <input
                        type={'text'}
                        id={'name'}
                        key={'name'}
                        placeholder={'Ім\'я'}
                        required
                    />
                    <input
                        type={'text'}
                        id={'middlename'}
                        key={'middlename'}
                        placeholder={'По батькові'}
                        required
                    />
                    <input
                        type={'text'}
                        id={'student_id'}
                        key={'student_id'}
                        placeholder={'Студентський квиток'}
                        required
                    />
                </div>
                <button
                    type="submit"
                    className={classes.button}>
                    Зареєструватись
                </button>
            </form>
        </div>
    )
}

export default SignUp;
