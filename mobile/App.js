import { NavigationContainer } from '@react-navigation/native'
import { createNativeStackNavigator } from '@react-navigation/native-stack'

import { LoginScreen } from './screens/Login/Login'
import { RegisterScreen } from './screens/Register/Register'
import { StartScreen } from './screens/Start/Start'

const Stack = createNativeStackNavigator()

const defaultScreenOptions = {
    options: {
        headerShown: false,
    },
}

const App = () => {
    return (
        <NavigationContainer>
            <Stack.Navigator>
                {/* <Stack.Screen name="Test" component={TestScreen} {...defaultScreenOptions} /> */}
                <Stack.Screen name="Home" component={StartScreen} {...defaultScreenOptions} />
                <Stack.Screen name="Login" component={LoginScreen} {...defaultScreenOptions} />
                <Stack.Screen
                    name="Register"
                    component={RegisterScreen}
                    {...defaultScreenOptions}
                />
            </Stack.Navigator>
        </NavigationContainer>
    )
}

export default App
