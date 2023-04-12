import { useCallback } from 'react'
import { Text, View } from 'react-native'

import { Button } from '../../components/Button/Button'

import { styles } from './StartStyles'

export const StartScreen = ({ navigation }) => {
    const handleLoginClick = useCallback(() => {
        navigation.navigate('Login')
    }, [navigation])

    return (
        <View style={styles.container}>
            <View style={styles.titleContainer}>
                {/* <StarsRating /> */}
                <Text style={styles.title}>Привіт, користувач!</Text>
                <Text style={styles.subtitle}>Для продовження, увійди в обліковий запис</Text>
            </View>
            <View style={styles.buttonsContainer}>
                <Button onPress={handleLoginClick}>Увійти</Button>
            </View>
        </View>
    )
}
