import type { ErrorType } from '@/types';
import type { ApiErrorConstructor, IApiError, Message, Status } from './types';
export declare class ApiError implements IApiError {
    status: Status;
    message: Message;
    error?: ErrorType;
    constructor(params: ApiErrorConstructor);
    static internalServerError(error: ErrorType): ApiError;
    notify(): void;
}
