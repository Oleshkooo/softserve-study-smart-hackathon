import type { ApiSuccessConstructor, IApiSuccess } from './types';
export declare class ApiSuccess<T = any> implements IApiSuccess<T> {
    status: number;
    message: string;
    data?: T | null;
    constructor(params: ApiSuccessConstructor<T>);
}
