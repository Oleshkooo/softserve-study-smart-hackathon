import { StyleSheet } from 'react-native'

import { colorDark, colorWhite, textH5 } from '../../config/styles'

export const blockDisciplineStyles = StyleSheet.create({
    button: {
        display: 'flex',
        paddingLeft: 22,
        justifyContent: 'center',
        width: 310,
        paddingTop: 16,
        paddingBottom: 16,
        borderRadius: 20,
        backgroundColor: colorDark,
    },
    text: {
        color: colorWhite,
        fontSize: textH5,
        fontWeight: 'bold',
    },
})
