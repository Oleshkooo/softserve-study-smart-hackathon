import { useState } from 'react';
import { StyleSheet, TextInput } from 'react-native';
import { inputStyles } from './InputStyle';

export const Input = ({ value, setValue, placeholder, password = false }) => {
    return (
        <TextInput
            style={inputStyles.input}
            value={value}
            onChangeText={setValue}
            placeholder={placeholder}
            secureTextEntry={password}
            placeholderTextColor={'#ffffff'}
            color={'#ffffff'}
        />
    );
};
