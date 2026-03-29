import { NextRequest, NextResponse } from "next/server";
import { getWebhookDeliveryLogsData } from "@/lib/webhook-delivery-logs-data";
import type { WebhookDeliveryQuery } from "@/components/dashboard/types";

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    
    // Parse query parameters
    const page = parseInt(searchParams.get("page") || "1");
    const pageSize = parseInt(searchParams.get("pageSize") || "10");
    const search = searchParams.get("search") || "";
    const sort = searchParams.get("sort") || "time_desc";
    const statusFilter = searchParams.get("statusFilter")?.split(",").filter(Boolean) || [];
    const eventTypeFilter = searchParams.get("eventTypeFilter")?.split(",").filter(Boolean) || [];
    const tenantFilter = searchParams.get("tenantFilter")?.split(",").filter(Boolean) || [];

    // Validate parameters
    if (page < 1 || pageSize < 1 || pageSize > 100) {
      return NextResponse.json(
        { error: "Invalid pagination parameters" },
        { status: 400 }
      );
    }

    const validSorts = ["time_desc", "time_asc", "status_asc", "status_desc", "attempts_desc", "attempts_asc"];
    if (!validSorts.includes(sort)) {
      return NextResponse.json(
        { error: "Invalid sort parameter" },
        { status: 400 }
      );
    }

    const validStatuses = ["success", "failed", "pending", "retrying"];
    const invalidStatuses = statusFilter.filter(s => !validStatuses.includes(s));
    if (invalidStatuses.length > 0) {
      return NextResponse.json(
        { error: `Invalid status values: ${invalidStatuses.join(", ")}` },
        { status: 400 }
      );
    }

    const validEventTypes = ["tx.success", "tx.failed", "balance.low"];
    const invalidEventTypes = eventTypeFilter.filter(e => !validEventTypes.includes(e));
    if (invalidEventTypes.length > 0) {
      return NextResponse.json(
        { error: `Invalid event type values: ${invalidEventTypes.join(", ")}` },
        { status: 400 }
      );
    }

    // Fetch data
    const data = await getWebhookDeliveryLogsData(
      page,
      pageSize,
      search,
      sort,
      statusFilter,
      eventTypeFilter,
      tenantFilter
    );

    return NextResponse.json(data);
  } catch (error) {
    console.error("Error in webhook delivery logs API:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
