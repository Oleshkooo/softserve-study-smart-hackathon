import { View, Text } from 'react-native'

import { BlockDisciplines } from '../../components/BlockDisciplines/BlockDisciplines'
import { colorDark } from '../../config/styles'

export const TestScreen = ({ navigation }) => {
    return (
        <View
            style={{
                flex: 1,
                justifyContent: 'center',
                alignItems: 'center',
                backgroundColor: colorDark,
            }}
        >
            <BlockDisciplines navigate={navigation.navigate} numOfButtons={1000} />
        </View>
    )
}

export const TestScreenNext = ({ navigation, route }) => {
    const id = route.params.id

    return (
        <View
            style={{
                flex: 1,
                justifyContent: 'center',
                alignItems: 'center',
                backgroundColor: colorDark,
            }}
        >
            <Text>{id}</Text>
        </View>
    )
}
