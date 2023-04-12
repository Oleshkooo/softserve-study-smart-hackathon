import { NavigationContainer } from '@react-navigation/native'
import { createNativeStackNavigator } from '@react-navigation/native-stack'
import { StatusBar } from 'react-native'

import { DisciplineScreen } from './screens/Discipline/Discipline'
import { ListOfDisciplinesScreen } from './screens/ListDisciplines/ListOfDisciplines'
import { LoginScreen } from './screens/Login/Login'
import { StartScreen } from './screens/Start/Start'

const Stack = createNativeStackNavigator()

const defaultScreenOptions = {
    options: {
        headerShown: false,
    },
}

const App = () => {
    return (
        <>
            <StatusBar backgroundColor="transparent" translucent />
            <NavigationContainer>
                <Stack.Navigator>
                    <Stack.Screen name="Start" component={StartScreen} {...defaultScreenOptions} />
                    {/* <Stack.Screen name="Home" component={StartScreen} {...defaultScreenOptions} /> */}
                    <Stack.Screen name="Login" component={LoginScreen} {...defaultScreenOptions} />
                    {/* <Stack.Screen name="Discipline" component={DisciplineScreen} {...defaultScreenOptions} /> */}

                    <Stack.Screen
                        name="Discipline"
                        component={DisciplineScreen}
                        {...defaultScreenOptions}
                    />
                    <Stack.Screen
                        name="ListOfDisciplinesScreen"
                        component={ListOfDisciplinesScreen}
                        {...defaultScreenOptions}
                    />
                </Stack.Navigator>
            </NavigationContainer>
        </>
    )
}

export default App
