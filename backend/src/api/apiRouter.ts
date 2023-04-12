import { Router } from 'express'

import { loginRouter, universityRouter } from './routes'

import { studentRouter } from '@/api/routes/studentRouter'
import { adminRouter } from './routes/adminRouter'

const apiRouter: Router = Router()

apiRouter.use('/university', universityRouter)
apiRouter.use('/login', loginRouter)
apiRouter.use('/student', studentRouter)
apiRouter.use('/admin', adminRouter)

export { apiRouter }
