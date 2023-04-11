import { Text, View } from "react-native"
import { colorLight, styles as mainStyles } from "../../config/styles"
import { Input } from "../../components/input/Input"
import { useState } from "react"
import { Button } from "../../components/button/Button"

export const SignUp = () => {
    const [name, setName] = useState('')
    const [surname, setSurname] = useState('')
    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')
    const [patronymic, setPatronymic] = useState('')
    const [studentTicket, setStudentTicket] = useState('')

    return (
        <View 
            style={{
                flex: 1,
                justifyContent: 'center',
                alignItems: 'center',
            }}>
            <View style={{flex: 1, justifyContent: 'flex-start',top: 30,gap: 21}}>
                <Text style={{color: colorLight,fontSize: 32,textAlign: "center",padding: 20}}>Реєстрація облікового запису</Text>
                <Input value={email} setValue={setEmail} placeholder="Email"/>
                <Input value={password} setValue={setPassword} placeholder="Пароль" password={true}/>
                <Input value={name} setValue={setName} placeholder="Ім'я"/>
                <Input value={surname} setValue={setSurname} placeholder="Прізвище"/>
                <Input value={patronymic} setValue={setPatronymic} placeholder="По-батькові"/>
                <Input value={studentTicket} setValue={setStudentTicket} placeholder="Номер студентського квитка"/>
            </View>
            <View style={{flex: 1, justifyContent: 'flex-end',bottom: 90}}>
                <Button onPress={() => {}}>Зареєструватися</Button>
            </View>
        </View>
    )
}
