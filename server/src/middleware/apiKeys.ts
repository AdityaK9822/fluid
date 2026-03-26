import { NextFunction, Request, Response } from "express";
import { AppError } from "../errors/AppError";
import prisma from "../utils/db";

export interface ApiKeyConfig {
  key: string;
  tenantId: string;
  name: string;
  tier: "free" | "pro";
  maxRequests: number;
  windowMs: number;
  dailyQuotaStroops: number;
}

function getApiKeyFromHeader(req: Request): string | undefined {
  const headerValue = req.header("x-api-key");
  if (typeof headerValue !== "string") return undefined;
  const apiKey = headerValue.trim();
  return apiKey.length > 0 ? apiKey : undefined;
}

export function maskApiKey(apiKey: string): string {
  if (apiKey.length <= 8) return `${apiKey.slice(0, 2)}***`;
  return `${apiKey.slice(0, 4)}...${apiKey.slice(-4)}`;
}

async function validateApiKey(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
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

  const keyRecord = await prisma.apiKey.findUnique({
    where: { key: apiKey },
  });

  if (!keyRecord) {
    return next(new AppError("Invalid API key.", 403, "AUTH_FAILED"));
  }

  const apiKeyConfig: ApiKeyConfig = {
    key: keyRecord.key,
    tenantId: keyRecord.tenantId,
    name: keyRecord.name,
    tier: keyRecord.tier as "free" | "pro",
    maxRequests: keyRecord.maxRequests,
    windowMs: keyRecord.windowMs,
    dailyQuotaStroops: Number(keyRecord.dailyQuotaStroops),
  };

  res.locals.apiKey = apiKeyConfig;
  next();
}

export function apiKeyMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  validateApiKey(req, res, next).catch(next);
}
