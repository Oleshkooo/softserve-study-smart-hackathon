import { PixelRatio } from 'react-native'

export const getPixels = size => PixelRatio.getPixelSizeForLayoutSize(size)
