import React, { memo } from 'react'
import { Pressable, Text } from 'react-native'

import { buttonStyles } from './ButtonStyles'

export const Button = memo(({ onPress, children }) => {
    return (
        <Pressable style={buttonStyles.button} onPress={onPress}>
            <Text style={buttonStyles.text}>{children}</Text>
        </Pressable>
    )
})
