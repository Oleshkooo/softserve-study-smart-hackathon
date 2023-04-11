import React from 'react';
import { Text, StyleSheet, Pressable } from 'react-native';

export const Button = ({ onPress, children }) => {
  return (
    <Pressable style={buttonStyles.button} onPress={onPress}>
      <Text style={buttonStyles.text}>{children}</Text>
    </Pressable>
  );
}