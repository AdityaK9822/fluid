import { z } from "zod";
import { WEBHOOK_EVENT_TYPES } from "../services/webhookEventTypes";

const WebhookEventTypeSchema = z.enum(WEBHOOK_EVENT_TYPES);

export const UpdateWebhookSchema = z
  .object({
    webhookUrl: z
      .union([z.string().url(), z.literal(""), z.null()])
      .optional()
      .transform((value) => (value === "" ? null : value)),
    webhookSecret: z
      .string()
      .trim()
      .min(1, "Webhook secret cannot be empty")
      .nullable()
      .optional(),
    eventTypes: z.array(WebhookEventTypeSchema).optional(),
  })
  .refine(
    ({ eventTypes, webhookSecret, webhookUrl }) =>
      webhookSecret !== undefined ||
      webhookUrl !== undefined ||
      eventTypes !== undefined,
    {
      message: "At least one webhook field must be provided",
    },
  );

export type UpdateWebhookRequest = z.infer<typeof UpdateWebhookSchema>;
