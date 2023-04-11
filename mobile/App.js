import { StyleSheet, View, Text } from 'react-native';

const Stack

export default function App() {

    return (
        <View style={styles.container}>
            <Start/>
        </View>
    )

}

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: '#000000',
        alignItems: 'center',
        justifyContent: 'center',
    },
});
