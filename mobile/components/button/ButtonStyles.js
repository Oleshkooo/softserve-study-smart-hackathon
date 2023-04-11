import { StyleSheet } from "react-native";



export const buttonStyles = StyleSheet.create({
    button: {
        backgroundColor: colorDark,
        borderRadius: 10,
        width: "250px",

        paddingTop: "16px",
        paddingBottom: "16px",

        display: "flex",
        justifyContent: "center",
        alignItems: "center",
    },
    text: {
        color: colorLight
    }
})
