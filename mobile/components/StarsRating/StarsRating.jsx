import { MaterialIcons } from '@expo/vector-icons'
import React, { useState } from 'react'
import {
    Animated,
    SafeAreaView,
    StyleSheet,
    Text,
    TouchableWithoutFeedback,
    View,
} from 'react-native'

export const StarsRating = () => {
    const [starRating, setStarRating] = useState(null)

    const animatedButtonScale = new Animated.Value(1)
    const animatedStarColor = new Animated.Value(0)

    const handlePressIn = () => {
        Animated.parallel([
            Animated.spring(animatedButtonScale, {
                toValue: 1.5,
                useNativeDriver: true,
                speed: 50,
                bounciness: 4,
            }),
            Animated.timing(animatedStarColor, {
                toValue: 1,
                duration: 200,
                useNativeDriver: false,
            }),
        ]).start()
    }

    const handlePressOut = () => {
        Animated.parallel([
            Animated.spring(animatedButtonScale, {
                toValue: 1,
                useNativeDriver: true,
                speed: 50,
                bounciness: 4,
            }),
            Animated.timing(animatedStarColor, {
                toValue: 0,
                duration: 200,
                useNativeDriver: false,
            }),
        ]).start()
    }

    const animatedScaleStyle = {
        transform: [{ scale: animatedButtonScale }],
    }

    const animatedStarColorStyle = {
        color: animatedStarColor.interpolate({
            inputRange: [0, 1],
            outputRange: ['#ffffff', '#ffb300'],
        }),
    }

    return (
        <SafeAreaView style={{ flex: 1 }}>
            <View style={styles.container}>
                <Text style={styles.heading}>{starRating ? `${starRating}` : 'Tap to rate'}</Text>
                <View style={styles.stars}>
                    <TouchableWithoutFeedback
                        onPressIn={handlePressIn}
                        onPressOut={handlePressOut}
                        onPress={() => setStarRating(1)}
                    >
                        <Animated.View style={[animatedScaleStyle]}>
                        <Animated.View style={animatedScaleStyle}>
                        <MaterialIcons
                                name={starRating >= 1 ? 'star' : 'star-border'}
                                size={32}
                                style={
                                    starRating >= 1 ? styles.starSelected : styles.starUnselected
                                }
                            />
                        </Animated.View>
                        </Animated.View>
                    </TouchableWithoutFeedback>
                    <TouchableWithoutFeedback
                        onPressIn={handlePressIn}
                        onPressOut={handlePressOut}
                        onPress={() => setStarRating(2)}
                    >
                        <Animated.View style={[animatedScaleStyle]}>
                        <Animated.View style={animatedScaleStyle}>
                        <MaterialIcons
                                name={starRating >= 1 ? 'star' : 'star-border'}
                                size={32}
                                style={
                                    starRating >= 1 ? styles.starSelected : styles.starUnselected
                                }
                            />
                    </Animated.View>
                        </Animated.View>
                    </TouchableWithoutFeedback>
                    <TouchableWithoutFeedback
                        onPressIn={handlePressIn}
                        onPressOut={handlePressOut}
                        onPress={() => setStarRating(1)}
                    >
                        <Animated.View style={animatedScaleStyle}>
                            <MaterialIcons
                                name={starRating >= 1 ? 'star' : 'star-border'}
                                size={32}
                                style={
                                    starRating >= 1 ? styles.starSelected : styles.starUnselected
                                }
                            />
                        </Animated.View>
                    </TouchableWithoutFeedback>
                    <TouchableWithoutFeedback
                        onPressIn={handlePressIn}
                        onPressOut={handlePressOut}
                        onPress={() => setStarRating(2)}
                    >
                        <Animated.View style={animatedScaleStyle}>
                            <MaterialIcons
                                name={starRating >= 2 ? 'star' : 'star-border'}
                                size={32}
                                style={
                                    starRating >= 2 ? styles.starSelected : styles.starUnselected
                                }
                            />
                        </Animated.View>
                    </TouchableWithoutFeedback>
                    <TouchableWithoutFeedback
                        onPressIn={handlePressIn}
                        onPressOut={handlePressOut}
                        onPress={() => setStarRating(3)}
                    >
                        <Animated.View style={animatedScaleStyle}>
                        <Animated.View style={animatedScaleStyle}>
                        <MaterialIcons
                                name={starRating >= 4 ? 'star' : 'star-border'}
                                size={32}
                                style={
                                    starRating >= 4 ? styles.starSelected : styles.starUnselected
                                }
                            />
                           </Animated.View>
                        </Animated.View>
                    </TouchableWithoutFeedback>
                    <TouchableWithoutFeedback
                        onPressIn={handlePressIn}
                        onPressOut={handlePressOut}
                        onPress={() => setStarRating(4)}
                    >
                        <Animated.View style={animatedScaleStyle}>
                            <MaterialIcons
                                name={starRating >= 4 ? 'star' : 'star-border'}
                                size={32}
                                style={
                                    starRating >= 4 ? styles.starSelected : styles.starUnselected
                                }
                            />
                        </Animated.View>
                    </TouchableWithoutFeedback>
                    <TouchableWithoutFeedback
                        onPressIn={handlePressIn}
                        onPressOut={handlePressOut}
                        onPress={() => setStarRating(5)}
                    >
                        <Animated.View style={animatedScaleStyle}>
                            <MaterialIcons
                                name={starRating >= 5 ? 'star' : 'star-border'}
                                size={32}
                                style={
                                    starRating >= 5 ? styles.starSelected : styles.starUnselected
                                }
                            />
                        </Animated.View>
                    </TouchableWithoutFeedback>
                </View>
            </View>
        </SafeAreaView>
    )
}

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: '#000000',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 20,
    },
    heading: {
        fontSize: 24,
        fontWeight: 'bold',
        marginBottom: 20,
    },
    stars: {
        display: 'flex',
        flexDirection: 'row',
    },
    starUnselected: {
        color: '#ffffff',
    },
    starSelected: {
        color: '#ffb300',
    },
})
