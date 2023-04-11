import { PixelRatio } from 'react-native'

export const getDp = (size) => {
    return PixelRatio.roundToNearestPixel(size / PixelRatio.get())
}