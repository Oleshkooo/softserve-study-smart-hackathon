import { useMemo, useState } from 'react'
import { ScrollView, Text, View } from 'react-native'

import { Item } from '../../components/Item/Item'
import { colorBlack, colorWhite, textH3 } from '../../config/styles'

import { styles } from './DisciplineStyle'

export const DisciplineScreen = ({ navigation, route }) => {
    const { data } = route.params
    const [nameDiscipline, setNameDiscipline] = useState(data.name)
    const [nameTeacher, setNameTeacher] = useState(data.teacher)
    const [emailTeacher, setEmailTeacher] = useState(data.teacherEmail)
    const [numOfLabs, setNumOfLabs] = useState(0)

    const items = useMemo(() =>
        data.labs.map((l, i) => {
            return (
                <View key={i} style={{ marginTop: 16 }}>
                    <Item text={l.name} onPress={() => {}} />
                </View>
            )
        }),
    )

    return (
        <ScrollView style={{ backgroundColor: colorBlack }}>
            <View style={{ marginLeft: 43, marginTop: 50 }}>
                <View style={{ color: colorWhite, marginTop: 40, marginBottom: 30 }}>
                    <Text style={styles.nameDiscipline}>{nameDiscipline}</Text>
                </View>
                <View style={{ flex: 1 }}>
                    <Text style={{ fontSize: textH3, color: colorWhite }}>
                        Викладач: {nameTeacher}
                    </Text>
                </View>
                <View>
                    <Text style={{ fontSize: textH3, color: colorWhite, marginVertical: 15 }}>
                        Email: {emailTeacher}
                    </Text>
                </View>

                {items}
            </View>
        </ScrollView>
    )
}
