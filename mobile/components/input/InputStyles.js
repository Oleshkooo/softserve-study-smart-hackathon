import { StyleSheet } from 'react-native'

import { colorWhite, textH5 } from '../../config/styles'

export const inputStyles = StyleSheet.create({
    input: {
        paddingHorizontal: 16,
        width: 300,
        height: 52,
        borderWidth: 1,
        borderRadius: 12,
        borderColor: colorWhite,
        fontSize: textH5,
        alignContent: 'center',
        justifyContent: 'center',
        color: '#222222',
    },
})
