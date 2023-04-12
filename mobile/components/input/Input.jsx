import { memo } from 'react'
import { TextInput } from 'react-native'

import { colorSecondaryDark, colorWhite } from '../../config/styles'

import { inputStyles } from './InputStyles'

export const Input = memo(({ value, setValue, placeholder, password = false, style }) => {
    return (
        <TextInput
            style={{ ...inputStyles.input, ...style }}
            value={value}
            onChangeText={setValue}
            placeholder={placeholder}
            secureTextEntry={password}
            placeholderTextColor={colorSecondaryDark}
            color={colorWhite}
        />
    )
})
