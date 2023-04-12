import { Router } from 'express'

import { loginRouter, universityRouter } from './routes'

import { studentRouter } from '@/api/routes/studentRouter'

const apiRouter: Router = Router()

apiRouter.use('/university', universityRouter)
apiRouter.use('/login', loginRouter)
apiRouter.use('/student', studentRouter)

export { apiRouter }
