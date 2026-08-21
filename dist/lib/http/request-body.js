export class RequestBodyError extends Error {
    status;
    constructor(status, message) {
        super(message);
        this.name = 'RequestBodyError';
        this.status = status;
    }
}
function declaredLength(request) {
    const raw = request.headers.get('Content-Length');
    if (!raw || !/^\d+$/.test(raw))
        return null;
    const value = Number(raw);
    return Number.isSafeInteger(value) ? value : null;
}
export async function readBoundedJson(request, maxBytes) {
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
        throw new Error('maxBytes must be a positive safe integer');
    }
    const length = declaredLength(request);
    if (length !== null && length > maxBytes) {
        throw new RequestBodyError(413, 'Payload too large');
    }
    const reader = request.body?.getReader();
    if (!reader)
        throw new RequestBodyError(400, 'Invalid JSON');
    const chunks = [];
    let total = 0;
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done)
                break;
            if (!value)
                continue;
            total += value.byteLength;
            if (total > maxBytes) {
                await reader.cancel('payload-too-large').catch(() => undefined);
                throw new RequestBodyError(413, 'Payload too large');
            }
            chunks.push(value);
        }
    }
    finally {
        reader.releaseLock();
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
    }
    try {
        const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
        const parsed = JSON.parse(text);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            throw new Error('JSON object required');
        }
        return parsed;
    }
    catch (error) {
        if (error instanceof RequestBodyError)
            throw error;
        throw new RequestBodyError(400, 'Invalid JSON');
    }
}
//# sourceMappingURL=request-body.js.map