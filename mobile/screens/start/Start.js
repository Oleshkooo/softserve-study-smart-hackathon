import { Text, View } from 'react-native';
import { colorLight } from '../../config/styles';
import { Button } from '../../components/button/Button';
import { SwitchScene,login,signup } from '../switch/Switch';

export const Start = () => {
    return (
        <View
            style={{
                flex: 1,
                justifyContent: 'center',
                alignItems: 'center',
                
            }}>
            <View style={{flex: 1, justifyContent: 'flex-start',top: 253,gap: 21}}>
            <Text
                style={{
                    fontSize: 28,
                    color: colorLight,
                    fontWeight: 'bold',
                }}>
                Привіт, студенте!
            </Text>
            <Text
                style={{
                    fontSize: 24,
                    color: colorLight,
                }}>
                Виберіть опцію, щоб продовжити
            </Text>
            </View>
            <View style={{flex: 1, justifyContent: 'flex-end',gap: 30,bottom: 150}}>
                <Button onPress={() => {SwitchScene(login)}}>
                    Увійти
                </Button>
                <Button onPress={() => {SwitchScene(signup)}}>Зареєструватися</Button>
            </View>
        </View>
    );
};
