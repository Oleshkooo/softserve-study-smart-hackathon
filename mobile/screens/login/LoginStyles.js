import { StyleSheet } from 'react-native'

import { colorBlack, colorWhite, textH1 } from '../../config/styles'

export const styles = StyleSheet.create({
    container: {
        flex: 1,
        justifyContent: 'center',
        alignItems: 'center',
        backgroundColor: colorBlack,
    },
    inputsContainer: {
        flex: 1,
        alignItems: 'center',
        top: 220,
        gap: 21,
    },
    title: {
        color: colorWhite,
        fontSize: textH1,
        textAlign: 'center',
        padding: 20,
    },
    buttonsContainer: {
        justifyContent: 'flex-end',
        alignItems: 'center',
        marginBottom: 60, // Встановлюємо marginBottom замість bottom
    },
})
