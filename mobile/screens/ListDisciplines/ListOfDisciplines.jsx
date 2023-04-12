import { useCallback, useMemo } from 'react'
import { ScrollView, View } from 'react-native'

import { Item } from '../../components/Item/Item'
import { colorBlack } from '../../config/styles'

export const ListOfDisciplinesScreen = ({ route, navigation }) => {
    const { data } = route.params

    const handlePress = useCallback(i => {
        return () => {
            navigation.navigate('Discipline', { data: data.disciplines[i] })
        }
    }, [])

    const items = useMemo(
        () =>
            data.disciplines.map((d, i) => {
                return (
                    <View key={i} style={{ marginTop: 16 }}>
                        <Item text={d.name} onPress={handlePress(i)} />
                    </View>
                )
            }),
        [data],
    )

    return (
        <ScrollView style={{ backgroundColor: colorBlack, paddingHorizontal: 20, paddingTop: 50 }}>
            <View style={{ flex: 1, marginTop: 40, marginBottom: 20, alignItems: 'center' }}>
                {items}
            </View>
        </ScrollView>
    )
}
