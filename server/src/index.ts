import "dotenv/config"; 

import cors from "cors";
import express, { NextFunction, Request, Response } from "express";
import rateLimit from "express-rate-limit";

//  These imports depend on environment variables
import { loadConfig } from "./config";
import { feeBumpHandler } from "./handlers/feeBump";
import { updateWebhookHandler } from "./handlers/tenantWebhook";
import { healthHandler } from "./handlers/health";

// import { apiKeyMiddleware } from "./middleware/apiKeys";
import { apiKeyRateLimit } from "./middleware/rateLimit";
import { notFoundHandler, globalErrorHandler } from "./middleware/errorHandler";
import { AppError } from "./errors/AppError";

import { initializeLedgerMonitor } from "./workers/ledgerMonitor";
import { transactionStore } from "./workers/transactionStore";
import { authMiddleware } from "./middleware/auth";

const app = express();
app.use(express.json());

// Initialize config after dotenv has loaded the variables
const config = loadConfig();

// Rate limiter configuration
const limiter = rateLimit({
  windowMs: config.rateLimitWindowMs,
  max: config.rateLimitMax,
  message: {
    error: "Too many requests from this IP, please try again later.",
    code: "RATE_LIMITED",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// CORS configuration
const corsOptions = {
  credentials: true,
  origin: (
    origin: string | undefined,
    callback: (err: Error | null, allow?: boolean) => void,
  ) => {
    if (!origin) {
      callback(null, false);
      return;
    }
    if (
      config.allowedOrigins.includes("*") ||
      config.allowedOrigins.includes(origin)
    ) {
      callback(null, true);
      return;
    }
    callback(new Error("Origin not allowed by CORS"), false);
  },
};

app.use(cors(corsOptions));

// Handle CORS errors
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  if (err.message === "Origin not allowed by CORS") {
    return next(new AppError("CORS not allowed", 403, "AUTH_FAILED"));
  }

  next(err);
});

// Health check
app.get("/health", (req: Request, res: Response, next: NextFunction) => {
  healthHandler(req, res, next, config);
});

// Protected Fee Bump Route (Generic Middleware)
app.post(
  "/fee-bump",
  authMiddleware, 
  apiKeyRateLimit,
  limiter,
  (req: Request, res: Response, next: NextFunction) => {
    feeBumpHandler(req, res, next, config);
  },
);

// Tenant Webhook Management
app.patch("/tenant/webhook", authMiddleware, updateWebhookHandler);

// --- Test Routes ---
app.post("/test/add-transaction", (req: Request, res: Response) => {
  const { hash, status = "pending" } = req.body;
  if (!hash) return res.status(400).json({ error: "Transaction hash required" });
  transactionStore.addTransaction(hash, "test", status);
  res.json({ message: `Transaction ${hash} added` });
});

app.get("/test/transactions", (req: Request, res: Response) => {
  res.json({ transactions: transactionStore.getAllTransactions() });
});

//  Error Handling 
app.use(notFoundHandler);
app.use(createGlobalErrorHandler(slackNotifier));

let balanceMonitor: ReturnType<typeof initializeBalanceMonitor> | null = null;
let ledgerMonitor: ReturnType<typeof initializeLedgerMonitor> | null = null;
let shuttingDown = false;
let server: ReturnType<typeof app.listen> | null = null;

async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) {
    return;
  }

  shuttingDown = true;
  await slackNotifier.notifyServerLifecycle({
    detail: `Signal received: ${signal}`,
    phase: "stop",
    timestamp: new Date(),
  });

  ledgerMonitor?.stop();
  balanceMonitor?.stop();

  if (server) {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2_000).unref();
    return;
  }

  process.exit(0);
}

// --- Background Workers ---
let ledgerMonitor: any = null;
if (config.horizonUrl) {
  try {
    ledgerMonitor = initializeLedgerMonitor(config);
    ledgerMonitor.start();
    console.log("Ledger monitor worker started");
  } catch (error) {
    console.error("Failed to start ledger monitor:", error);
  }
}

// Final Server Start
app.listen(PORT, () => {
  console.log(`Fluid server running on http://0.0.0.0:${PORT}`);
  console.log(`Fee payers loaded: ${config.feePayerAccounts.length}`);
});
