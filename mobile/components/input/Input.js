import { useState } from 'react';
import { StyleSheet, TextInput } from 'react-native';
import { inputStyles } from './InputStyle';

export const Input = ({ placeholder, password = false }) => {
    const [text, setText] = useState('');

    return (
        <TextInput
            style={inputStyles.input}
            value={text}
            onChangeText={setText}
            placeholder={placeholder}
        />
    );
};
