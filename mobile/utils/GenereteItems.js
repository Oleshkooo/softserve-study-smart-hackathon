import React from 'react'

import { View } from 'react-native'

import { Item } from '../components/Item/Item'

export const generateItems = (numOfItems, textForItems, onPress) => {
    const items = []
    for (let i = 0; i < numOfItems; i++) {
        items.push(
            <View key={i} style={{ marginTop: 16 }}>
                <Item text={textForItems[i]} onPress={onPress} />
            </View>,
        )
    }
    return items
}
