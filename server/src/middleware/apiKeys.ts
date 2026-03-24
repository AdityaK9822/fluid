import { NextFunction, Request, Response } from "express";
import { AppError } from "../errors/AppError";

export interface ApiKeyConfig {
  key: string;
  name: string;
  tier: "free" | "pro";
  maxRequests: number;
  windowMs: number;
}

const API_KEYS = new Map<string, ApiKeyConfig>([
  [
    "fluid-free-demo-key",
    {
      key: "fluid-free-demo-key",
      name: "Demo Free dApp",
      tier: "free",
      maxRequests: 2,
      windowMs: 60_000,
    },
  ],
  [
    "fluid-pro-demo-key",
    {
      key: "fluid-pro-demo-key",
      name: "Demo Pro dApp",
      tier: "pro",
      maxRequests: 5,
      windowMs: 60_000,
    },
  ],
]);

function getApiKeyFromHeader(req: Request): string | undefined {
  const headerValue = req.header("x-api-key");

  if (typeof headerValue !== "string") {
    return undefined;
  }

  const apiKey = headerValue.trim();
  return apiKey.length > 0 ? apiKey : undefined;
}

export function maskApiKey(apiKey: string): string {
  if (apiKey.length <= 8) {
    return `${apiKey.slice(0, 2)}***`;
  }

  return `${apiKey.slice(0, 4)}...${apiKey.slice(-4)}`;
}

export function apiKeyMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const apiKey = getApiKeyFromHeader(req);

  if (!apiKey) {
    return next(
      new AppError(
        "Missing API key. Provide a valid x-api-key header to access this endpoint.",
        401,
        "AUTH_FAILED"
      )
    );
  }

  const apiKeyConfig = API_KEYS.get(apiKey);

  if (!apiKeyConfig) {
    return next(new AppError("Invalid API key.", 403, "AUTH_FAILED"));
  }

  res.locals.apiKey = apiKeyConfig;
  next();
}

export function getApiKeyConfig(apiKey: string): ApiKeyConfig | undefined {
  return API_KEYS.get(apiKey);
}
