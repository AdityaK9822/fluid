import { createLogger, serializeError } from "./utils/logger";
import express, { NextFunction, Request, Response } from "express";
import {
  getHorizonFailoverClient,
  initializeHorizonFailoverClient,
} from "./horizon/failoverClient";
import {
  getLedgerMonitor,
  initializeLedgerMonitor,
} from "./workers/ledgerMonitor";
import { globalErrorHandler, notFoundHandler } from "./middleware/errorHandler";

import { AppError } from "./errors/AppError";
import { apiKeyMiddleware } from "./middleware/apiKeys";
import { apiKeyRateLimit } from "./middleware/rateLimit";
import { AlertService } from "./services/alertService";
import { initializeBalanceMonitor } from "./workers/balanceMonitor";
import { initializeLedgerMonitor } from "./workers/ledgerMonitor";
import { transactionStore } from "./workers/transactionStore";

const logger = createLogger({ component: "server" });

dotenv.config();

const app = express();
app.use(express.json());

const config = loadConfig();
const alertService = new AlertService(config.alerting);

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

const corsOptions = {
  origin: (
    origin: string | undefined,
    callback: (err: Error | null, allow?: boolean) => void,
  ) => {
    if (!origin) {
      callback(null, false);
      return;
    }

    if (
      config.allowedOrigins.length === 0 ||
      config.allowedOrigins.includes(origin)
    ) {
      callback(null, true);
      return;
    }

    callback(new Error("Origin not allowed by CORS"), false);
  },
  credentials: true,
};

app.use(cors(corsOptions));

app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  if (err.message === "Origin not allowed by CORS") {
    return next(new AppError("CORS not allowed", 403, "AUTH_FAILED"));
  }
  next(err);
});

app.get("/health", (req: Request, res: Response) => {
  const accounts = config.signerPool.getSnapshot().map((account) => ({
    publicKey: account.publicKey,
    status: account.active ? "active" : "inactive",
    in_flight: account.inFlight,
    total_uses: account.totalUses,
    sequence_number: account.sequenceNumber,
    balance: account.balance,
  }));

  res.json({
    status: "ok",
    fee_payers: accounts,
    horizon_nodes:
      getHorizonFailoverClient()?.getNodeStatuses() ??
      getLedgerMonitor()?.getNodeStatuses() ??
      config.horizonUrls.map((url) => ({
        url,
        state: "Active",
        consecutiveFailures: 0,
      })),
    total: accounts.length,
    low_balance_alerting: {
      enabled:
        config.alerting.lowBalanceThresholdXlm !== undefined &&
        alertService.isEnabled() &&
        Boolean(config.horizonUrl),
      threshold_xlm: config.alerting.lowBalanceThresholdXlm ?? null,
      check_interval_ms: config.alerting.checkIntervalMs,
      cooldown_ms: config.alerting.cooldownMs,
      slack_configured: Boolean(config.alerting.slackWebhookUrl),
      email_configured: Boolean(config.alerting.email),
    },
  });
});

// Fee bump endpoint
app.post(
  "/fee-bump",
  apiKeyMiddleware,
  apiKeyRateLimit,
  limiter,
  (req: Request, res: Response, next: NextFunction) => {
    feeBumpHandler(req, res, next, config);
  },
);

app.post("/test/add-transaction", (req: Request, res: Response) => {
  const { hash, status = "pending", tenantId = "test-tenant" } = req.body;

  if (!hash) {
    res.status(400).json({ error: "Transaction hash is required" });
    return;
  }

  transactionStore.addTransaction(hash, tenantId, status);
  res.json({ message: `Transaction ${hash} added with status ${status}` });
});

app.get("/test/transactions", (req: Request, res: Response) => {
  const transactions = transactionStore.getAllTransactions();
  res.json({ transactions });
});

app.post(
  "/test/alerts/low-balance",
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!alertService.isEnabled()) {
        return res.status(400).json({
          error:
            "No alert transport configured. Set Slack webhook or SMTP env vars first.",
        });
      }

      await alertService.sendTestAlert(config);
      res.json({ message: "Test low-balance alert sent" });
    } catch (error) {
      next(error);
    }
  },
);

// 404 - must come after all routes
app.use(notFoundHandler);
app.use(globalErrorHandler);

const PORT = process.env.PORT || 3000;

let ledgerMonitor: ReturnType<typeof initializeLedgerMonitor> | null = null;
if (config.horizonUrls.length > 0) {
  try {
    ledgerMonitor = initializeLedgerMonitor(config);
    ledgerMonitor.start();
    logger.info("Ledger monitor worker started");
  } catch (error) {
    logger.error({ ...serializeError(error) }, "Failed to start ledger monitor");
  }
} else {
  logger.info("No Horizon URLs configured; ledger monitor disabled");
}

let balanceMonitor: any = null;
if (
  config.horizonUrl &&
  config.alerting.lowBalanceThresholdXlm !== undefined &&
  alertService.isEnabled()
) {
  try {
    balanceMonitor = initializeBalanceMonitor(config, alertService);
    balanceMonitor.start();
    console.log("Balance monitor worker started");
  } catch (error) {
    console.error("Failed to start balance monitor:", error);
  }
} else {
  console.log(
    "Low balance alerting disabled - missing Horizon URL, threshold, or alert transport",
  );
}

app.listen(PORT, () => {
  console.log(`Fluid server running on http://0.0.0.0:${PORT}`);
  console.log(`Fee payers loaded: ${config.feePayerAccounts.length}`);
  config.feePayerAccounts.forEach((a, i) => {
    console.log(`  [${i + 1}] ${a.publicKey}`);
  });
});
