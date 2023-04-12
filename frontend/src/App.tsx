import { createContext, useState } from 'react'
import { Route, Routes } from 'react-router-dom'
import Home from './components/home/Home'
import Main from './components/main/Main'
import SignIn from './components/signin/SignIn'
import SignUp from './components/signup/SignUp'

export interface Labs extends JSX.IntrinsicAttributes {
    name: string
    rating: number
    message: string
    points: number
}

export interface IDiscipline extends JSX.IntrinsicAttributes {
    name: string
    teacher: string
    teacherEmail: string
    labs: Labs[]
}

export interface DisciplineObject extends JSX.IntrinsicAttributes {
    [index: number]: {
        name: string
        teacher: string
        teacherEmail: string
        labs: Labs[]
    }
}

export interface IUser extends JSX.IntrinsicAttributes {
    email: string
    password: string
    perms: string
    name: string
    university_id: string
    speciality_id: string
    disciplines: DisciplineObject[]
}

export interface ContextObject extends JSX.IntrinsicAttributes {
    data: IUser
    setData: (user: IUser) => void
    selectedDiscipline: number
    setSelectedDiscipline: (name: string) => void
    selectedLab: Labs
    setSelectedLab: (lab: Labs) => void
    students: IUser[]
    setStudents: (users: IUser[]) => void
    selectedStudent: IUser
    setSelectedStudent: (users: IUser) => void
    teacherRating: number
    setTeacherRating: (rating: number) => void
    teacherHover: number
    setTeacherHover: (rating: number) => void
    studentRating: number
    setStudentRating: (rating: number) => void
    studentHover: number
    setStudentHover: (rating: number) => void
}

let contextDb = createContext<ContextObject | null>(null)

export const App = () => {
    const [selectedDiscipline, setSelectedDiscipline] = useState<IDiscipline>()
    const [data, setData] = useState<IUser>()
    const [selectedLab, setSelectedLab] = useState<Labs>()
    const [students, setStudents] = useState<IUser[]>()
    const [selectedStudent, setSelectedStudent] = useState<IUser[]>()
    const [teacherRating, setTeacherRating] = useState<number>(0)
    const [teacherHover, setTeacherHover] = useState<number>(0)
    const [studentRating, setStudentRating] = useState<number>(0)
    const [studentHover, setStudentHover] = useState<number>(0)

    const CtxData: ContextObject = {
        data: data,
        setData: setData,
        selectedDiscipline: selectedDiscipline,
        setSelectedDiscipline: setSelectedDiscipline,
        selectedLab: selectedLab,
        setSelectedLab: setSelectedLab,
        students: students,
        setStudents: setStudents,
        selectedStudent: selectedStudent,
        setSelectedStudent: setSelectedStudent,
        teacherRating: teacherRating,
        setTeacherRating: setTeacherRating,
        teacherHover: teacherHover,
        setTeacherHover: setTeacherHover,
        studentRating: studentRating,
        setStudentRating: setStudentRating,
        studentHover: studentHover,
        setStudentHover: setStudentHover,
    }

    return (
        <contextDb.Provider value={CtxData}>
            <Routes>
                <Route path={'/start'} element={<Home />} />
                <Route path={'/signup'} element={<SignUp />} />
                <Route path={'/signin'} element={<SignIn />} />
                <Route path={'/'} element={<Main />} />
            </Routes>
        </contextDb.Provider>
    )
}

export default App
export { contextDb }
