export declare class RequestBodyError extends Error {
    readonly status: 400 | 413;
    constructor(status: 400 | 413, message: string);
}
export declare function readBoundedJson(request: Request, maxBytes: number): Promise<Record<string, unknown>>;
