import { Router } from 'express'

import { get, put } from '@/api/controllers/student'

const studentRouter: Router = Router()

studentRouter.get('/', get)
studentRouter.put('/', put)

export { studentRouter }
