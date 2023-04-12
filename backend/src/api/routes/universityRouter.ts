import { Router } from 'express'

import { get } from '@/api/controllers/university'

const universityRouter: Router = Router()

universityRouter.get('/', get)

export { universityRouter }
