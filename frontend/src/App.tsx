import { Route, Routes } from 'react-router-dom'
import Home from './components/home/Home'
import SignIn from './components/signin/SignIn'
import SignUp from './components/signup/SignUp'

export const App = () => {
    return (
      <Routes>
        <Route path={'/'} element={<Home />} />
        <Route path={'/signup'} element={<SignUp />} />
        <Route path={'/signin'} element={<SignIn />} />
      </Routes>
    )
}

export default App
