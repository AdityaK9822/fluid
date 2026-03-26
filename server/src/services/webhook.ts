import { Job, Queue, Worker } from "bullmq";
import { createLogger, serializeError } from "../utils/logger";

import Redis from "ioredis";
import axios from "axios";
import prisma from "../utils/db";

const connection = new Redis(process.env.REDIS_URL || "redis://localhost:6379");
export const webhookLogger = createLogger({ component: "webhook_service" });

export const webhookQueue = new Queue("webhook-delivery", {
  connection,
  defaultJobOptions: {
    attempts: 5,
    backoff: {
      type: "exponential",
      delay: 60000, // 1 minute initial delay
    },
    removeOnComplete: true,
  },
});

interface WebhookJobData {
  deliveryId: string;
}

export class WebhookService {
  static async queueWebhook (tenantId: string, url: string, payload: any) {
    const delivery = await prisma.webhookDelivery.create({
      data: {
        tenantId,
        url,
        payload,
        status: "pending",
      },
    });

    await webhookQueue.add("deliver", {
      deliveryId: delivery.id,
    });

    return delivery;
  }

  async dispatch (
    tenantId: string,
    hash: string,
    status: "success" | "failed"
  ): Promise<void> {
    const tenant = await prisma.tenant.findUnique({
      where: { id: tenantId },
      select: { id: true, webhookUrl: true },
    });

    if (!tenant) {
      webhookLogger.warn(
        { tenant_id: tenantId, tx_hash: hash, status },
        "Tenant not found for webhook dispatch"
      );
      return;
    }

    if (!tenant.webhookUrl) {
      webhookLogger.debug(
        { tenant_id: tenant.id, tx_hash: hash, status },
        "Tenant has no webhook URL configured"
      );
      return;
    }

    try {
      const response = await fetch(tenant.webhookUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ hash, status }),
      });

      if (!response.ok) {
        webhookLogger.error(
          {
            response_status: response.status,
            status,
            tenant_id: tenant.id,
            tx_hash: hash,
            webhook_url: tenant.webhookUrl,
          },
          "Webhook dispatch returned non-2xx response"
        );
        return;
      }

      webhookLogger.info(
        { status, tenant_id: tenant.id, tx_hash: hash, webhook_url: tenant.webhookUrl },
        "Webhook dispatched successfully"
      );
    } catch (error) {
      webhookLogger.error(
        {
          ...serializeError(error),
          status,
          tenant_id: tenant.id,
          tx_hash: hash,
          webhook_url: tenant.webhookUrl,
        },
        "Network error during webhook dispatch"
      );
    }
  }
}

// Worker logic
export const startWebhookWorker = () => {
  const worker = new Worker<WebhookJobData>(
    "webhook-delivery",
    async (job: Job<WebhookJobData>) => {
      const { deliveryId } = job.data;
      const delivery = await prisma.webhookDelivery.findUnique({
        where: { id: deliveryId },
      });

      if (!delivery) return;

      try {
        webhookLogger.info(
          {
            attempt: job.attemptsMade + 1,
            delivery_id: deliveryId,
            tenant_id: delivery.tenantId,
            url: delivery.url,
          },
          "Attempting webhook delivery"
        );

        await axios.post(delivery.url, delivery.payload, {
          timeout: 5000,
          headers: {
            "Content-Type": "application/json",
            "X-Webhook-ID": deliveryId,
          },
        });

        await prisma.webhookDelivery.update({
          where: { id: deliveryId },
          data: {
            status: "success",
            retryCount: job.attemptsMade,
          },
        });

        webhookLogger.info(
          { delivery_id: deliveryId, tenant_id: delivery.tenantId, url: delivery.url },
          "Webhook delivery succeeded"
        );
      } catch (error: any) {
        const errorMessage = error.response?.data || error.message;
        webhookLogger.error(
          {
            ...serializeError(error),
            attempt: job.attemptsMade + 1,
            delivery_id: deliveryId,
            tenant_id: delivery.tenantId,
            url: delivery.url,
            webhook_error: errorMessage,
          },
          "Webhook delivery failed"
        );

        await prisma.webhookDelivery.update({
          where: { id: deliveryId },
          data: {
            status: "failed",
            retryCount: job.attemptsMade + 1,
            lastError: errorMessage.toString().substring(0, 500),
            nextAttempt: new Date(Date.now() + (job.opts.backoff as any).delay * Math.pow(2, job.attemptsMade)),
          },
        });

        throw error; // Let BullMQ handle the retry
      }
    },
    { connection }
  );

  worker.on("failed", (job: Job<WebhookJobData> | undefined, err: Error) => {
    if (job && job.attemptsMade >= 5) {
      webhookLogger.error(
        {
          ...serializeError(err),
          attempts: job.attemptsMade,
          delivery_id: job.data.deliveryId,
          job_id: job.id,
        },
        "Webhook delivery failed permanently"
      );
    }
  });

  return worker;
};
