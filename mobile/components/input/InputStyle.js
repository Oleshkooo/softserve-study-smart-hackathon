import { StyleSheet } from 'react-native';
import { colorDark, colorLight } from '../../config/styles';

export const inputStyles = StyleSheet.create({
    input: {
        color: colorLight,
        backgroundColor: colorDark,
        paddingHorizontal: 16,
        width: 300,
        height: 52,
        borderWidth: 1,
        borderRadius: 3,
        borderColor: colorLight
    },
});
