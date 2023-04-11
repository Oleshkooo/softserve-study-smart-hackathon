import { StyleSheet, View, Text } from 'react-native';
import { Input } from './components/input/Input';

export default function App() {
    return (
        <View style={styles.container}>
            <Input placeholder="placeholder" />
        </View>
    );
}

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: '#000000',
        alignItems: 'center',
        justifyContent: 'center',
    },
});
