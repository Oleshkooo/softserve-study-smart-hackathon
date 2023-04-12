import { StyleSheet } from 'react-native'

import { colorBlack, colorWhite } from '../../config/styles'

export const styles = StyleSheet.create({
    button: {
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        width: 250,
        paddingTop: 16,
        paddingBottom: 16,
        borderRadius: 10,
        backgroundColor: colorWhite,
    },
    text: {
        color: colorBlack,
    },
})
