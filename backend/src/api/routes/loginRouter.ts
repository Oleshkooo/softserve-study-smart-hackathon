import { Router } from 'express'

import { post } from '@/api/controllers/login'

const loginRouter: Router = Router()

loginRouter.post('/', post)

export { loginRouter }
