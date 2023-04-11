import React from 'react';
import { blockDisciplineStyles } from './BlockDisciplineStyles';
import { Pressable, Text, View, ScrollView } from 'react-native';

export const BlockDiscipline = ({ numOfButtons }) => {
    const buttonLabels = Array.from({ length: numOfButtons }, (_, index) => `Button ${index + 1}`);

    const buttons = buttonLabels.map((label, index) => (
    <View key={index} style={{ padding: 10 }}>
      <Pressable style={blockDisciplineStyles.button} onPress={() => console.log(label)}>
        <Text style={blockDisciplineStyles.text}>{label}</Text>
      </Pressable>
    </View>
    ));

    return (
    <View style={{paddingHorizontal: 20,paddingTop: 40}}>
      <ScrollView style={{width: '100%'}}>
        {buttons}
      </ScrollView>
    </View>
    );
};
