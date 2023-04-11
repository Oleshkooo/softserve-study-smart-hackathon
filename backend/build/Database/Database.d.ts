type IsConnected = () => boolean;
type Connect = () => IsConnected | Promise<IsConnected>;
interface IDatabase {
    isConnected: IsConnected;
    connect: Connect;
}
export declare class Database implements IDatabase {
    private static instance;
    constructor();
    isConnected: IsConnected;
    connect: Connect;
}
export {};
