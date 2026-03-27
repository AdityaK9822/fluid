import { describe, expect, it, vi } from "vitest";
import { AppError } from "../errors/AppError";
import { createGlobalErrorHandler } from "./errorHandler";

describe("createGlobalErrorHandler", () => {
  it("alerts when an unexpected 5xx error occurs", () => {
    const notifier = {
      notifyServerError: vi.fn().mockResolvedValue(true),
    };
    const handler = createGlobalErrorHandler(notifier as any);
    const req = {
      header: vi.fn().mockReturnValue("req-500"),
      method: "POST",
      path: "/fee-bump",
    } as any;
    const res = {
      json: vi.fn(),
      status: vi.fn().mockReturnThis(),
    } as any;

    handler(new Error("submission failed"), req, res, vi.fn());

    expect(res.status).toHaveBeenCalledWith(500);
    expect(notifier.notifyServerError).toHaveBeenCalledWith(
      expect.objectContaining({
        method: "POST",
        path: "/fee-bump",
        requestId: "req-500",
        statusCode: 500,
      }),
    );
  });

  it("does not alert for 4xx app errors", () => {
    const notifier = {
      notifyServerError: vi.fn().mockResolvedValue(true),
    };
    const handler = createGlobalErrorHandler(notifier as any);
    const req = {
      header: vi.fn().mockReturnValue(undefined),
      method: "POST",
      path: "/fee-bump",
    } as any;
    const res = {
      json: vi.fn(),
      status: vi.fn().mockReturnThis(),
    } as any;

    handler(new AppError("bad request", 400, "INVALID_XDR"), req, res, vi.fn());

    expect(res.status).toHaveBeenCalledWith(400);
    expect(notifier.notifyServerError).not.toHaveBeenCalled();
  });
});
