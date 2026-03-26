import pino, { type Bindings, type Logger, type LoggerOptions } from "pino";

type SerializableError = {
    type?: string;
    message: string;
    stack?: string;
    code?: unknown;
    status?: unknown;
    status_code?: unknown;
    response_status?: unknown;
    response_data?: unknown;
};

const defaultLevel = process.env.LOG_LEVEL ??
    (process.env.NODE_ENV === "production" ? "info" : "debug");
const prettyLoggingEnabled =
    process.env.NODE_ENV !== "production" && process.env.LOG_PRETTY === "true";

const loggerOptions: LoggerOptions = {
    level: defaultLevel,
    timestamp: pino.stdTimeFunctions.isoTime,
    base: {
        service: "fluid-server",
        env: process.env.NODE_ENV ?? "development",
    },
    formatters: {
        level: (level) => ({ level }),
    },
};

const transport = prettyLoggingEnabled
    ? pino.transport({
        target: "pino-pretty",
        options: {
            colorize: true,
            singleLine: false,
            translateTime: "SYS:standard",
        },
    })
    : undefined;

export const logger = pino(loggerOptions, transport);

export function createLogger (bindings: Bindings): Logger {
    return logger.child(bindings);
}

export function serializeError (error: unknown): SerializableError {
    if (error instanceof Error) {
        const candidate = error as Error & {
            cause?: unknown;
            code?: unknown;
            response?: { data?: unknown; status?: unknown };
            status?: unknown;
            statusCode?: unknown;
        };

        return {
            type: error.name,
            message: error.message,
            stack: error.stack,
            code: candidate.code,
            status: candidate.status,
            status_code: candidate.statusCode,
            response_status: candidate.response?.status,
            response_data: candidate.response?.data,
        };
    }

    return {
        message: String(error),
    };
}