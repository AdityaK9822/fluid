import type { WebhookDeliveryPageData, WebhookDeliveryLog } from "@/components/dashboard/types";

// Sample data for development - replace with actual API call
const SAMPLE_WEBHOOK_DELIVERY_LOGS: WebhookDeliveryLog[] = [
  {
    id: "whdl_1234567890",
    tenantId: "tenant_001",
    tenantName: "Acme Corp",
    eventType: "tx.success",
    webhookUrl: "https://acme.example.com/webhooks/fluid",
    status: "success",
    attempts: 1,
    maxAttempts: 3,
    responseCode: 200,
    responseMessage: "OK",
    payload: {
      event: "tx.success",
      data: {
        transactionHash: "abc123...",
        tenantId: "tenant_001",
        amount: "100",
        asset: "XLM",
        timestamp: "2024-03-28T10:30:00Z"
      }
    },
    createdAt: "2024-03-28T10:30:15Z",
    updatedAt: "2024-03-28T10:30:15Z",
    nextRetryAt: null
  },
  {
    id: "whdl_1234567891",
    tenantId: "tenant_002",
    tenantName: "Tech Startup",
    eventType: "tx.failed",
    webhookUrl: "https://tech-startup.example.com/webhooks",
    status: "retrying",
    attempts: 2,
    maxAttempts: 3,
    responseCode: 500,
    responseMessage: "Internal Server Error",
    payload: {
      event: "tx.failed",
      data: {
        transactionHash: "def456...",
        tenantId: "tenant_002",
        error: "Insufficient balance",
        timestamp: "2024-03-28T10:25:00Z"
      }
    },
    createdAt: "2024-03-28T10:25:30Z",
    updatedAt: "2024-03-28T10:30:30Z",
    nextRetryAt: "2024-03-28T10:35:30Z"
  },
  {
    id: "whdl_1234567892",
    tenantId: "tenant_003",
    tenantName: "Finance Co",
    eventType: "balance.low",
    webhookUrl: "https://finance.example.com/api/webhooks",
    status: "failed",
    attempts: 3,
    maxAttempts: 3,
    responseCode: 404,
    responseMessage: "Not Found",
    payload: {
      event: "balance.low",
      data: {
        tenantId: "tenant_003",
        currentBalance: "50.5",
        threshold: "100",
        timestamp: "2024-03-28T10:20:00Z"
      }
    },
    createdAt: "2024-03-28T10:20:45Z",
    updatedAt: "2024-03-28T10:25:45Z",
    nextRetryAt: null
  },
  {
    id: "whdl_1234567893",
    tenantId: "tenant_001",
    tenantName: "Acme Corp",
    eventType: "tx.success",
    webhookUrl: "https://acme.example.com/webhooks/fluid",
    status: "pending",
    attempts: 0,
    maxAttempts: 3,
    responseCode: null,
    responseMessage: null,
    payload: {
      event: "tx.success",
      data: {
        transactionHash: "ghi789...",
        tenantId: "tenant_001",
        amount: "250",
        asset: "XLM",
        timestamp: "2024-03-28T10:35:00Z"
      }
    },
    createdAt: "2024-03-28T10:35:10Z",
    updatedAt: "2024-03-28T10:35:10Z",
    nextRetryAt: "2024-03-28T10:35:40Z"
  },
  {
    id: "whdl_1234567894",
    tenantId: "tenant_004",
    tenantName: "Retail Store",
    eventType: "tx.success",
    webhookUrl: "https://retail.example.com/webhook-endpoint",
    status: "success",
    attempts: 1,
    maxAttempts: 3,
    responseCode: 200,
    responseMessage: "OK",
    payload: {
      event: "tx.success",
      data: {
        transactionHash: "jkl012...",
        tenantId: "tenant_004",
        amount: "75",
        asset: "XLM",
        timestamp: "2024-03-28T10:15:00Z"
      }
    },
    createdAt: "2024-03-28T10:15:20Z",
    updatedAt: "2024-03-28T10:15:20Z",
    nextRetryAt: null
  }
];

export async function getWebhookDeliveryLogsData(
  page: number = 1,
  pageSize: number = 10,
  search: string = "",
  sort: string = "time_desc",
  statusFilter: string[] = [],
  eventTypeFilter: string[] = [],
  tenantFilter: string[] = []
): Promise<WebhookDeliveryPageData> {
  try {
    // In a real implementation, this would call your backend API
    // const response = await fetch(
    //   `/api/admin/webhooks/delivery-logs?page=${page}&pageSize=${pageSize}&search=${encodeURIComponent(search)}&sort=${sort}&statusFilter=${statusFilter.join(',')}&eventTypeFilter=${eventTypeFilter.join(',')}&tenantFilter=${tenantFilter.join(',')}`
    // );
    // const data = await response.json();

    // For now, return sample data
    const startIndex = (page - 1) * pageSize;
    const endIndex = startIndex + pageSize;
    const rows = SAMPLE_WEBHOOK_DELIVERY_LOGS.slice(startIndex, endIndex);

    return {
      rows,
      page,
      pageSize,
      totalRows: SAMPLE_WEBHOOK_DELIVERY_LOGS.length,
      totalPages: Math.ceil(SAMPLE_WEBHOOK_DELIVERY_LOGS.length / pageSize),
      sort: sort as any,
      search,
      statusFilter: statusFilter as any,
      eventTypeFilter: eventTypeFilter as any,
      tenantFilter,
      source: "sample"
    };
  } catch (error) {
    console.error("Failed to fetch webhook delivery logs:", error);
    
    // Return empty data on error
    return {
      rows: [],
      page,
      pageSize,
      totalRows: 0,
      totalPages: 0,
      sort: sort as any,
      search,
      statusFilter: statusFilter as any,
      eventTypeFilter: eventTypeFilter as any,
      tenantFilter,
      source: "sample"
    };
  }
}
