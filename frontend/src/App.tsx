import { Route, Routes } from 'react-router-dom'
import Home from './components/home/Home'
import SignIn from './components/signin/SignIn'
import SignUp from './components/signup/SignUp'
import Main from './components/main/Main'

export const App = () => {
    return (
      <Routes>
        <Route path={'/start'} element={<Home />} />
        <Route path={'/signup'} element={<SignUp />} />
        <Route path={'/signin'} element={<SignIn />} />
        <Route path={'/'} element={<Main />} />
      </Routes>
    )
}

export default App
