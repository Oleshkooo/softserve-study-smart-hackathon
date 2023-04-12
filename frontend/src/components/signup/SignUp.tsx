import { useEffect, useState, useContext } from 'react'
import BackButton from '../utils/BackButton'
import classes from './SignUp.module.css'
import { getUniversities, signUpUser } from '../API'    
import { useNavigate } from 'react-router-dom'
import { contextDb } from '../main/Main'

function SignUp() {
    const [errMsg, setErrMsg] = useState<string>('')
    const [universities, setUniversities] = useState(null)
    const [selectedUni, setSelectedUni] = useState(0)

    const CtxData = useContext(contextDb);
    const navigator = useNavigate();

    function handleCreateUser(e) {
        e.preventDefault()

        const data = {
            email: e.target.email.value,
            password: e.target.password.value,
            name: `${e.target.surname.value} ${e.target.name.value} ${e.target.middlename.value}`,
            universityId: universities[selectedUni].id,
            specialityId: universities[selectedUni].specialities.find(u => u.name === e.target.spec.value).id,
            perms: 'student'
        }

        if (data.password.length < 8) setErrMsg('Довжина паролю понна бути не менше 8 символів')

        setErrMsg('')

        signUpUser(data).then(res => {
            console.log(res);
            CtxData?.setData(res.data.data)
            setErrMsg('');
            navigator('/');
        })
        .catch(err => {
            setErrMsg('Неможливо створити даний профіль')
        })
    }

    function handleChangeUni(e) {
        setSelectedUni(universities.findIndex(u => u.name === e.target.value))
    }

    useEffect(() => {
        getUniversities().then(res => setUniversities(res.data.data))
    }, [])

    return (
        <div className={classes.main}>
            <BackButton />
            <h2>Реєстрація облікового запису</h2>
            <form className={classes.form} onSubmit={handleCreateUser}>
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
                    <input type={'text'} id={'name'} key={'name'} placeholder={"Ім'я"} required />
                    <input
                        type={'text'}
                        id={'middlename'}
                        key={'middlename'}
                        placeholder={'По батькові'}
                        required
                    />
                    {universities ? (
                        <>
                            <select id={'uni'} key={'uni'} onChange={handleChangeUni}>
                                {universities.map(item => (
                                    <option id={item.id}>{item.name}</option>
                                ))}
                            </select>
                            <select id={'spec'} key={'spec'}>
                                {universities[selectedUni].specialities.map(d => (
                                    <option id={d.id}>{d.name}</option>
                                ))}
                            </select>
                        </>
                    ) : (
                        <p>Завантаження...</p>
                    )}
                </div>
                {errMsg ? <p>{errMsg}</p> : <></>}
                <button type="submit" className={classes.button}>
                    Зареєструватись
                </button>
            </form>
        </div>
    )
}

export default SignUp
