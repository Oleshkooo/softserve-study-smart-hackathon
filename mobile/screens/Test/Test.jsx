import { View } from 'react-native'

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
            <BlockDisciplines numOfButtons={1000} />
        </View>
    )
}
