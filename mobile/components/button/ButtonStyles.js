import { StyleSheet } from 'react-native'

import { colorDark, colorLight } from '../../config/styles'

export const buttonStyles = StyleSheet.create({
    button: {
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        width: 250,
        paddingTop: 16,
        paddingBottom: 16,
        borderRadius: 10,
        backgroundColor: colorLight,
    },
    text: {
        color: colorDark,
    },
})
