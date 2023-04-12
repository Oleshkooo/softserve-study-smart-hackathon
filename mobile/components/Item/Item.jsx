import React from 'react'
import { Pressable, Text } from 'react-native'

import { blockDisciplineStyles } from './ItemDisciplinesStyles'

export const Item = ({ onPress, text }) => {
    return (
        <Pressable style={blockDisciplineStyles.button} onPress={onPress}>
            <Text style={blockDisciplineStyles.text}>{text}</Text>
        </Pressable>
    )
}
