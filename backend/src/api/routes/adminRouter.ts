import { Router } from 'express'

import { del, post } from '@/api/controllers/admin'

const adminRouter: Router = Router()

adminRouter.post('/user', post)
adminRouter.delete('/user', del)

export { adminRouter }
