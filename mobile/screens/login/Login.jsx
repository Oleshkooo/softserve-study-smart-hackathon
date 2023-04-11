import { useCallback, useState } from 'react'
import { Text, View } from 'react-native'

import { Button } from '../../components/Button/Button'
import { Input } from '../../components/Input/Input'

import { styles } from './LoginStyles'

export const LoginScreen = () => {
    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')

    const handleLoginClick = useCallback(() => {
        console.log(email, password)
    }, [email, password])

    return (
        <View style={styles.container}>
            <View style={styles.inputsContainer}>
                <Text style={styles.title}>Вхід до облікового запису</Text>
                <Input value={email} setValue={setEmail} placeholder="Email" />
                <Input value={password} setValue={setPassword} placeholder="Пароль" password />
            </View>
            <View style={styles.buttonsContainer}>
                <Button onPress={handleLoginClick}>Увійти</Button>
            </View>
        </View>
    )
}
