/// <reference types="mongoose/types/aggregate" />
/// <reference types="mongoose/types/callback" />
/// <reference types="mongoose/types/collection" />
/// <reference types="mongoose/types/connection" />
/// <reference types="mongoose/types/cursor" />
/// <reference types="mongoose/types/document" />
/// <reference types="mongoose/types/error" />
/// <reference types="mongoose/types/expressions" />
/// <reference types="mongoose/types/helpers" />
/// <reference types="mongoose/types/middlewares" />
/// <reference types="mongoose/types/indexes" />
/// <reference types="mongoose/types/models" />
/// <reference types="mongoose/types/mongooseoptions" />
/// <reference types="mongoose/types/pipelinestage" />
/// <reference types="mongoose/types/populate" />
/// <reference types="mongoose/types/query" />
/// <reference types="mongoose/types/schemaoptions" />
/// <reference types="mongoose/types/schematypes" />
/// <reference types="mongoose/types/session" />
/// <reference types="mongoose/types/types" />
/// <reference types="mongoose/types/utility" />
/// <reference types="mongoose/types/validation" />
/// <reference types="mongoose/types/virtuals" />
/// <reference types="mongoose/types/inferschematype" />
import { Schema } from 'mongoose';
interface ILab {
    name: string;
    rating: number;
    message: string;
}
export interface IDiscipline {
    name: string;
    teacher: string;
    teacherEmail: string;
    labs: ILab[];
}
interface ISpecialitie {
    id: string;
    name: string;
    disciplines: IDiscipline[];
}
export interface IUniversity {
    _id: number;
    id: string;
    name: string;
    abbr: string;
    specialities: ISpecialitie[];
}
export declare const DisciplineSchema: Schema<IDiscipline, import("mongoose").Model<IDiscipline, any, any, any, import("mongoose").Document<unknown, any, IDiscipline> & Omit<IDiscipline & {
    _id: import("mongoose").Types.ObjectId;
}, never>, any>, {}, {}, {}, {}, import("mongoose").DefaultSchemaOptions, IDiscipline, import("mongoose").Document<unknown, {}, import("mongoose").FlatRecord<IDiscipline>> & Omit<import("mongoose").FlatRecord<IDiscipline> & {
    _id: import("mongoose").Types.ObjectId;
}, never>>;
export declare const UniversityModel: import("mongoose").Model<any, {}, {}, {}, any, any>;
export {};
