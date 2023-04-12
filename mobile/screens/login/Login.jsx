import { useCallback, useState } from 'react'
import { Keyboard, Text, TouchableWithoutFeedback, View } from 'react-native'

import { Button } from '../../components/Button/Button'
import { Input } from '../../components/Input/Input'
import { SERVER_URL } from '../../config/vars'

import { textH1 } from '../../config/styles'

import { styles } from './LoginStyles'

export const LoginScreen = ({ navigation }) => {
    const { navigate } = navigation

    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')
    const [error, setError] = useState('')

    const handleLoginClick = useCallback(async () => {
        try {
            if (!email || !password) {
                return
            }

            const res = await fetch(`${SERVER_URL}/api/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    email,
                    password,
                }),
            })
            const data = await res.json()

            if (data.status !== 200) {
                setError(data.message)
                return
            }

            navigate('ListOfDisciplinesScreen', data)
        } catch (error) {
            console.error(error)
        }
    })

    return (
        <TouchableWithoutFeedback onPress={Keyboard.dismiss} accessible={false}>
            <View style={styles.container}>
                <View style={styles.inputsContainer}>
                    <Text style={styles.title}>Вхід до облікового запису</Text>
                    <Input value={email} setValue={setEmail} placeholder="Email" />
                    <Input value={password} setValue={setPassword} placeholder="Пароль" password />
                    <Text
                        style={{
                            fontSize: textH1,
                            color: 'red',
                        }}
                    >
                        {error}
                    </Text>
                </View>
                <View style={styles.buttonsContainer}>
                    <Button onPress={handleLoginClick}>Увійти</Button>
                </View>
            </View>
        </TouchableWithoutFeedback>
    )
}
