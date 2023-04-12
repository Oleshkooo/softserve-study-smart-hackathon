import type { ApiSuccessConstructor, IApiSuccess } from './types'

export class ApiSuccess<T = any> implements IApiSuccess<T> {
    public status: number
    public message: string
    public data?: T | null

    constructor(params: ApiSuccessConstructor<T>) {
        const { status, message, data } = params

        this.status = status
        this.message = message
        this.data = data
    }
}
