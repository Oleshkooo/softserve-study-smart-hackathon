import { Text,View } from "react-native";
import { colorLight } from "../../config/styles";
import { Button } from "../../components/button/Button";
import { getDp } from "../../utils/getDp";

export const Start = () => {
    return (
        <View>
            <Text style={{fontSize: 28, color: colorLight,fontWeight: "bold"}}>Привіт, студенте!</Text>
            <Text style={{fontSize: 24, color: colorLight}}>Виберіть опцію, щоб продовжити</Text>
            <Button onPress={() => {}} style={{marginTop: 20}}>Увійти</Button>
            <Button onPress={() => {}} style={{marginTop: 20}}>Зареєструватися</Button>
            <marginTop style={{marginTop: 20}}/>
           </View>
        );
}
