import React, { memo } from 'react'
import { Pressable, Text } from 'react-native'

import { styles } from './ButtonStyles'

export const Button = memo(({ onPress, children }) => {
    return (
        <Pressable style={styles.button} onPress={onPress}>
            <Text style={styles.text}>{children}</Text>
        </Pressable>
    )
})
