import { Text, View } from "react-native"
import { colorLight, styles as mainStyles } from "../../config/styles"
import { Input } from "../../components/input/Input"
import { useState } from "react"
import { Button } from "../../components/button/Button"

export const Login = () => {
    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')

    return (
    <View>
        <View style={{flex: 1, alignItems: 'center',top: 200,gap: 21}}>
            <Text style={{color: colorLight,fontSize: 28,textAlign: "center",padding: 20}}>Вхід до облікового запису</Text>
            <Input value={email} setValue={setEmail} placeholder="Email"/>
            <Input value={password} setValue={setPassword} placeholder="Пароль" password={true}/>
        </View>

        <View style={{flex: 1, justifyContent: 'flex-end',bottom: 90,alignItems: 'center'}}>
            <Button onPress={() => {}}>Увійти</Button>
        </View>
    </View>
    )
}
