import { memo } from 'react'
import { TextInput } from 'react-native'

import { inputStyles } from './InputStyles'

export const Input = memo(({ value, setValue, placeholder, password = false }) => {
    return (
        <TextInput
            style={inputStyles.input}
            value={value}
            onChangeText={setValue}
            placeholder={placeholder}
            secureTextEntry={password}
            placeholderTextColor="#ffffff"
            color="#ffffff"
        />
    )
})
