import { StyleSheet, View } from 'react-native'
import { Button } from './components/button/Button'

export default function App() {
    return (
        <View style={styles.container}>
            <Button onPress={() => {}}>Some button</Button>
        </View>
    )
}

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: '#000',
        alignItems: 'center',
        justifyContent: 'center',
    },
})
