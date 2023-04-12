import axios from 'axios'

export function registerUser() {}

export async function logInUser(data) {
    return await axios
        .post('http://localhost:4000/api/login', data)
        .then(res => {
            return res
        })
        .catch(err => {
            return err
        })
}

export async function signUpUser(data) {
    return await axios
        .post('http://localhost:4000/api/admin/user', data)
        .then(res => {
            return res
        })
        .catch(err => {
            return err
        })
}

export async function putStudentRating(data) {
    return await axios
        .put('http://localhost:4000/api/student/', data)
        .then(res => {
            return res
        })
        .catch(err => {
            return err
        })
}

export async function getUniversities() {
    return await axios
        .get('http://localhost:4000/api/university')
        .then(res => {
            return res
        })
        .catch(err => {
            return err
        })
}