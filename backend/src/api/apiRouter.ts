import { Router } from 'express'

import { universityRouter } from './routes'

const apiRouter: Router = Router()

apiRouter.use('/university', universityRouter)

export { apiRouter }
