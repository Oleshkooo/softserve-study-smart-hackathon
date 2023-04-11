import React from 'react';
import {TextInput} from 'react-native';
import {Input} from './InputStyle'

const Input = ({placeholder}) => {
  const [text, onChangeText] = React.useState('');

  return (
      <TextInput
        style={styles.input}
        onChangeText={onChangeText}
        placeholder={placeholder}
        value={text}
      />
  );
};


export default Input;