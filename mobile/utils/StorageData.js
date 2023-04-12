// import AsyncStorage from '@react-native-async-storage/async-storage'

// // const storeData = async (nameValue)value => {
// //     try {
// //         await AsyncStorage.setItem('@storage_Key, value)
// //     } catch (e) {
// //         // saving error
// //     }
// // }

// export const getData = async storage_Key => {
//     try {
//         const jsonValue = await AsyncStorage.getItem(storage_Key)
//         return jsonValue != null ? JSON.parse(jsonValue) : null
//     } catch (e) {
//         // error reading value
//     }
// }

// const getValue = async nameValue => {
//     try {
//         const value = await AsyncStorage.getItem(nameValue)
//         if (value !== null) {
//             // value previously stored
//         }
//     } catch (e) {
//         // error reading value
//     }
// }
// export const storeData = async (data, storageKey) => {
//     try {
//         const jsonValue = JSON.stringify(data)
//         await AsyncStorage.setItem(storageKey, jsonValue)
//         console.log('Data successfully stored')
//         console.log('Data: ', data)
//     } catch (e) {
//         console.error(e)
//     }
// }
