import { StyleSheet } from 'react-native'

import { colorBlack, colorWhite, textH3Display, textH4 } from '../../config/styles'

export const styles = StyleSheet.create({
    container: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: colorBlack,
    },
    titleContainer: {
        flex: 1,
        justifyContent: 'flex-start',
        top: 253,
        gap: 21,
    },
    title: {
        fontSize: textH3Display,
        color: colorWhite,
        fontWeight: 'bold',
        textAlign: 'center',
    },
    subtitle: {
        fontSize: textH4,
        color: colorWhite,
        textAlign: 'center',
    },
    buttonsContainer: {
        flex: 1,
        justifyContent: 'flex-end',
        gap: 30,
        bottom: 150,
    },
})
