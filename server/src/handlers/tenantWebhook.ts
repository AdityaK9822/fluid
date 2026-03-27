import { NextFunction, Request, Response } from "express";
import { ApiKeyConfig } from "../middleware/apiKeys";
import { UpdateWebhookSchema } from "../schemas/tenantWebhook";
import {
  deserializeWebhookEventTypes,
  serializeWebhookEventTypes,
} from "../services/webhookEventTypes";
import { prisma } from "../utils/db";

const tenantModel = (prisma as any).tenant as {
  findUnique: (args: any) => Promise<any | null>;
  update: (args: any) => Promise<any>;
};

function toWebhookSettingsResponse(tenant: {
  id: string;
  name?: string | null;
  webhookUrl?: string | null;
  webhookEventTypes?: string | null;
  webhookSecret?: string | null;
  updatedAt?: Date | null;
}) {
  return {
    tenantId: tenant.id,
    tenantName: tenant.name ?? null,
    webhookUrl: tenant.webhookUrl ?? null,
    eventTypes: deserializeWebhookEventTypes(tenant.webhookEventTypes),
    webhookSecretConfigured: Boolean(tenant.webhookSecret),
    updatedAt: tenant.updatedAt?.toISOString() ?? null,
  };
}

export async function getWebhookSettingsHandler(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const apiKeyConfig = res.locals.apiKey as ApiKeyConfig;
  const { tenantId } = apiKeyConfig;

  try {
    const tenant = await tenantModel.findUnique({
      where: { id: tenantId },
      select: {
        id: true,
        name: true,
        webhookUrl: true,
        webhookEventTypes: true,
        webhookSecret: true,
        updatedAt: true,
      },
    });

    if (!tenant) {
      res.status(404).json({ error: "Tenant not found" });
      return;
    }

    res.status(200).json(toWebhookSettingsResponse(tenant));
  } catch (error) {
    next(error);
  }
}

export async function updateWebhookHandler(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const result = UpdateWebhookSchema.safeParse(req.body);

  if (!result.success) {
    res.status(400).json({ error: result.error.format() });
    return;
  }

  const apiKeyConfig = res.locals.apiKey as ApiKeyConfig;
  const { tenantId } = apiKeyConfig;

  try {
    const existingTenant = await tenantModel.findUnique({
      where: { id: tenantId },
      select: {
        id: true,
        name: true,
        webhookUrl: true,
        webhookEventTypes: true,
        webhookSecret: true,
        updatedAt: true,
      },
    });

    if (!existingTenant) {
      res.status(404).json({ error: "Tenant not found" });
      return;
    }

    const tenant = await tenantModel.update({
      where: { id: tenantId },
      data: {
        webhookUrl:
          result.data.webhookUrl === undefined
            ? existingTenant.webhookUrl
            : result.data.webhookUrl,
        webhookSecret:
          result.data.webhookSecret === undefined
            ? existingTenant.webhookSecret
            : result.data.webhookSecret,
        webhookEventTypes:
          result.data.eventTypes === undefined
            ? existingTenant.webhookEventTypes
            : serializeWebhookEventTypes(result.data.eventTypes),
      },
      select: {
        id: true,
        name: true,
        webhookUrl: true,
        webhookEventTypes: true,
        webhookSecret: true,
        updatedAt: true,
      },
    });

    res.status(200).json(toWebhookSettingsResponse(tenant));
  } catch (error) {
    next(error);
  }
}
