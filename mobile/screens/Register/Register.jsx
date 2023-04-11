import { useCallback, useState } from 'react'
import { Text, View } from 'react-native'

import { Button } from '../../components/Button/Button'
import { Input } from '../../components/Input/Input'

import { styles } from './RegisterStyles'

export const RegisterScreen = () => {
    const [name, setName] = useState('')
    const [surname, setSurname] = useState('')
    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')
    const [patronymic, setPatronymic] = useState('')
    const [studentTicket, setStudentTicket] = useState('')

    const handleRegisterClick = useCallback(() => {
        console.log(name, surname, email, password, patronymic, studentTicket)
    }, [name, surname, email, password, patronymic, studentTicket])

    return (
        <View style={styles.container}>
            <View style={styles.inputsContainer}>
                <Text style={styles.title}>Реєстрація облікового запису</Text>
                <Input value={email} setValue={setEmail} placeholder="Email" />
                <Input value={password} setValue={setPassword} placeholder="Пароль" password />
                <Input value={name} setValue={setName} placeholder="Ім'я" />
                <Input value={surname} setValue={setSurname} placeholder="Прізвище" />
                <Input value={patronymic} setValue={setPatronymic} placeholder="По-батькові" />
                <Input
                    value={studentTicket}
                    setValue={setStudentTicket}
                    placeholder="Номер студентського квитка"
                />
            </View>
            <View style={styles.buttonsContainer}>
                <Button onPress={handleRegisterClick}>Зареєструватись</Button>
            </View>
        </View>
    )
}
