import type { ErrorType } from '@/types'

export type Status = number
export type Message = string
export interface IApi {
    status: Status
    message: Message
}

// ApiError
export interface IApiError extends IApi {
    error?: ErrorType
}
export interface ApiErrorConstructor {
    status: Status
    message: Message
    error?: ErrorType
}

// ApiSuccess
export interface IApiSuccess<T = any> extends IApi {
    data?: T | null
}
export interface ApiSuccessConstructor<T = any> {
    status: Status
    message: Message
    data?: T | null
}
