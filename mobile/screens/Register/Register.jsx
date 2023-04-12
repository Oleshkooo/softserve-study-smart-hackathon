import { useState } from 'react'
import { Keyboard, Text, TouchableWithoutFeedback, View } from 'react-native'

import { Button } from '../../components/Button/Button'
import { Input } from '../../components/Input/Input'

import { styles } from './RegisterStyles'

export const RegisterScreen = () => {
    const [name, setName] = useState('')
    const [surname, setSurname] = useState('')
    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')
    const [patronymic, setPatronymic] = useState('')
    const [university, setUniversity] = useState('')
    const [speciality, setSpeciality] = useState('')

    return (
        <TouchableWithoutFeedback onPress={Keyboard.dismiss} accessible={false}>
            <View style={styles.container}>
                <View>
                    <Text style={styles.title}>Реєстрація облікового запису</Text>
                    <Input value={email} setValue={setEmail} placeholder="Email" autoFocus />
                    <Input
                        value={password}
                        setValue={setPassword}
                        placeholder="Пароль"
                        password
                        autoFocus
                    />
                    <Input value={name} setValue={setName} placeholder="Ім'я" autoFocus />
                    <Input value={surname} setValue={setSurname} placeholder="Прізвище" autoFocus />
                    <Input
                        value={patronymic}
                        setValue={setPatronymic}
                        placeholder="По-батькові"
                        autoFocus
                    />
                    <Input
                        value={university}
                        setValue={setUniversity}
                        placeholder="Університет"
                        autoFocus
                    />
                    <Input
                        value={speciality}
                        setValue={setSpeciality}
                        placeholder="Спеціальність"
                    />
                </View>
                <View style={styles.buttonsContainer}>
                    <Button>Зареєструватись</Button>
                </View>
            </View>
        </TouchableWithoutFeedback>
    )
}
