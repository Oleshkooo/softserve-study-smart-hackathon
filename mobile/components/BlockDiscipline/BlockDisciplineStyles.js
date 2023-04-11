import { StyleSheet } from 'react-native';
import { colorLight, colorBlockDiscipline } from '../../config/styles';

export const blockDisciplineStyles = StyleSheet.create({
    button: {
        display: 'flex',
        paddingLeft: 22,
        justifyContent: 'center',
        width: 310,
        paddingTop: 16,
        paddingBottom: 16,
        borderRadius: 10,
        backgroundColor: colorBlockDiscipline,
    },
    text: {
        color: colorLight,
        fontSize: 14,
        fontWeight: 'bold',
        

    },
});
