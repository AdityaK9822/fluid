export const WEBHOOK_EVENT_TYPES = [
  "tx.success",
  "tx.failed",
  "balance.low",
] as const;

export type WebhookEventType = (typeof WEBHOOK_EVENT_TYPES)[number];

const WEBHOOK_EVENT_TYPE_SET = new Set<WebhookEventType>(WEBHOOK_EVENT_TYPES);

export function getDefaultWebhookEventTypes(): WebhookEventType[] {
  return [...WEBHOOK_EVENT_TYPES];
}

export function isWebhookEventType(value: string): value is WebhookEventType {
  return WEBHOOK_EVENT_TYPE_SET.has(value as WebhookEventType);
}

export function normalizeWebhookEventTypes(
  values: Iterable<string> | null | undefined,
): WebhookEventType[] {
  if (!values) {
    return getDefaultWebhookEventTypes();
  }

  const normalized = Array.from(new Set(values))
    .filter(isWebhookEventType);

  if (normalized.length === 0) {
    return getDefaultWebhookEventTypes();
  }

  return WEBHOOK_EVENT_TYPES.filter((eventType) => normalized.includes(eventType));
}

export function serializeWebhookEventTypes(
  values: Iterable<string> | null | undefined,
): string {
  return JSON.stringify(normalizeWebhookEventTypes(values));
}

export function deserializeWebhookEventTypes(
  value: string | null | undefined,
): WebhookEventType[] {
  if (!value) {
    return getDefaultWebhookEventTypes();
  }

  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed)
      ? normalizeWebhookEventTypes(parsed.filter((entry): entry is string => typeof entry === "string"))
      : getDefaultWebhookEventTypes();
  } catch {
    return getDefaultWebhookEventTypes();
  }
}

export function mapTransactionStatusToWebhookEventType(
  status: "success" | "failed",
): WebhookEventType {
  return status === "success" ? "tx.success" : "tx.failed";
}
