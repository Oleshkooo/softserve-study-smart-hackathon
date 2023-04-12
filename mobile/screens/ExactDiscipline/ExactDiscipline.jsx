import { Text, View } from 'react-native'

import { colorBlack, colorWhite } from '../../config/styles'

export const ExactDisciplineScreen = ({ navigation, route }) => {
    const data = route.params

    return (
        <View
            style={{
                flex: 1,
                justifyContent: 'flex-start',
                backgroundColor: colorBlack,
            }}
        >
            <Text
                style={{

                    marginTop: 80,
                }}
            >
                Викладач: {data.teacher}
                {JSON.stringify(data)}
            </Text>
        </View>
    )
}
