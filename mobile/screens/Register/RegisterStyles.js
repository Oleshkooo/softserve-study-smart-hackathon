import { StyleSheet } from 'react-native'

import { colorDark, colorLight, textH1 } from '../../config/styles'

export const styles = StyleSheet.create({
    container: {
        flex: 1,
        justifyContent: 'center',
        alignItems: 'center',
        backgroundColor: colorDark,
    },
    inputsContainer: {
        flex: 1,
        alignItems: 'center',
        top: 80,
        gap: 21,
    },
    title: {
        color: colorLight,
        fontSize: textH1,
        textAlign: 'center',
        padding: 20,
    },
    buttonsContainer: {
        flex: 1,
        justifyContent: 'flex-end',
        bottom: 90,
    },
})
