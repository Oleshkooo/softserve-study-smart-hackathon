import { StyleSheet } from 'react-native'

import { colorDark, colorLight, textH3Display, textH4 } from '../../config/styles'

export const styles = StyleSheet.create({
    container: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: colorDark,
    },
    titleContainer: {
        flex: 1,
        justifyContent: 'flex-start',
        top: 253,
        gap: 21,
    },
    title: {
        fontSize: textH3Display,
        color: colorLight,
        fontWeight: 'bold',
        textAlign: 'center',
    },
    subtitle: {
        fontSize: textH4,
        color: colorLight,
        textAlign: 'center',
    },
    buttonsContainer: {
        flex: 1,
        justifyContent: 'flex-end',
        gap: 30,
        bottom: 150,
    },
})
