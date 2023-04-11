import { useCallback } from 'react'
import { Text, View } from 'react-native'

import { Button } from '../../components/Button/Button'

import { styles } from './StartStyles'

export const StartScreen = ({ navigation }) => {
    const handleLoginClick = useCallback(() => {
        navigation.navigate('Login')
    }, [navigation])
    const handleRegisterClick = useCallback(() => {
        navigation.navigate('Register')
    }, [navigation])

    return (
        <View style={styles.container}>
            <View style={styles.titleContainer}>
                <Text style={styles.title}>Привіт, студенте!</Text>
                <Text style={styles.subtitle}>Виберіть опцію, щоб продовжити</Text>
            </View>
            <View style={styles.buttonsContainer}>
                <Button onPress={handleLoginClick}>Увійти</Button>
                <Button onPress={handleRegisterClick}>Зареєструватися</Button>
            </View>
        </View>
    )
}
