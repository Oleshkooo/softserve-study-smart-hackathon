import React, { memo, useMemo } from 'react'
import { Pressable, ScrollView, Text, View } from 'react-native'

import { blockDisciplineStyles } from './BlockDisciplinesStyles'

export const BlockDisciplines = memo(({ numOfButtons }) => {
    const buttonLabels = useMemo(
        () => Array.from({ length: numOfButtons }, (_, index) => `Button ${index + 1}`),
        [numOfButtons],
    )

    const buttons = useMemo(
        () =>
            buttonLabels.map((label, index) => (
                <View key={index} style={{ padding: 10 }}>
                    <Pressable
                        style={blockDisciplineStyles.button}
                        onPress={() => console.log(label)}
                    >
                        <Text style={blockDisciplineStyles.text}>{label}</Text>
                    </Pressable>
                </View>
            )),
        [buttonLabels],
    )

    return (
        <View style={{ paddingHorizontal: 20, paddingTop: 40 }}>
            <ScrollView style={{ width: '100%' }}>{buttons}</ScrollView>
        </View>
    )
})
