import cors from "cors";
import dotenv from "dotenv";
import express, { NextFunction, Request, Response } from "express";
import rateLimit from "express-rate-limit";
import { createLogger, serializeError } from "./utils/logger";
import redisClient from "./utils/redis";
import { RedisRateLimitStore } from "./utils/redisRateLimitStore";
import { loadConfig } from "./config";
import { AppError } from "./errors/AppError";
import { feeBumpBatchHandler, feeBumpHandler } from "./handlers/feeBump";
import {
  getHorizonFailoverClient,
  initializeHorizonFailoverClient,
} from "./horizon/failoverClient";
import { apiKeyMiddleware } from "./middleware/apiKeys";
import {
  listApiKeysHandler,
  revokeApiKeyHandler,
  upsertApiKeyHandler,
} from "./handlers/adminApiKeys";
import {
  addSignerHandler,
  listSignersHandler,
  removeSignerHandler,
} from "./handlers/adminSigners";
import {
  createGlobalErrorHandler,
  notFoundHandler,
} from "./middleware/errorHandler";
import {
  createCheckoutSessionHandler,
  stripeWebhookHandler,
} from "./handlers/stripe";
import { apiKeyRateLimit } from "./middleware/rateLimit";
import { AlertService } from "./services/alertService";
import {
  SlackNotifier,
  loadSlackNotifierOptionsFromEnv,
} from "./services/slackNotifier";
import {
  hydratePersistedSigners,
  listAdminSigners,
} from "./services/signerRegistry";
import { initializeBalanceMonitor } from "./workers/balanceMonitor";
import {
  getLedgerMonitor,
  initializeLedgerMonitor,
} from "./workers/ledgerMonitor";
import { transactionStore } from "./workers/transactionStore";

const logger = createLogger({ component: "server" });

dotenv.config();

const app = express();
const config = loadConfig();
const slackNotifier = new SlackNotifier(loadSlackNotifierOptionsFromEnv());
const alertService = new AlertService(config.alerting, slackNotifier);
const PORT = Number.parseInt(process.env.PORT || "3000", 10);

// Stripe webhook needs raw body for signature verification.
app.post(
  "/webhooks/stripe",
  express.raw({ type: "application/json" }),
  stripeWebhookHandler,
);

app.use(express.json());

const windowSeconds = Math.max(1, Math.ceil(config.rateLimitWindowMs / 1000));
let limiterStore: unknown;
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const RateLimitRedis = require("rate-limit-redis");
  const RedisStore = RateLimitRedis.default || RateLimitRedis;
  limiterStore = new RedisStore({ client: redisClient, expiry: windowSeconds });
} catch {
  try {
    limiterStore = new RedisRateLimitStore(redisClient, windowSeconds);
  } catch (error) {
    logger.error(
      { ...serializeError(error) },
      "Failed to initialize rate-limit store",
    );
  }
}

const limiter = rateLimit({
  windowMs: config.rateLimitWindowMs,
  max: config.rateLimitMax,
  message: {
    error: "Too many requests from this IP, please try again later.",
    code: "RATE_LIMITED",
  },
  standardHeaders: true,
  legacyHeaders: false,
  store: limiterStore as any,
});

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
      config.allowedOrigins.length === 0 ||
      config.allowedOrigins.includes(origin)
    ) {
      callback(null, true);
      return;
    }

    callback(new Error("Origin not allowed by CORS"), false);
  },
};

app.use(cors(corsOptions));

app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  if (err.message === "Origin not allowed by CORS") {
    return next(new AppError("CORS not allowed", 403, "AUTH_FAILED"));
  }

  next(err);
});

app.get("/health", async (req: Request, res: Response, next: NextFunction) => {
  try {
    const signers = await listAdminSigners(config);

    res.json({
      status: "ok",
      fee_payers: signers.map((account) => ({
        balance: account.balance,
        in_flight: account.inFlight,
        publicKey: account.publicKey,
        sequence_number: account.sequenceNumber,
        source: account.source,
        status: account.status,
        total_uses: account.totalUses,
      })),
      horizon_nodes:
        getHorizonFailoverClient()?.getNodeStatuses() ??
        getLedgerMonitor()?.getNodeStatuses() ??
        config.horizonUrls.map((url) => ({
          consecutiveFailures: 0,
          state: "Active",
          url,
        })),
      low_balance_alerting: {
        check_interval_ms: config.alerting.checkIntervalMs,
        cooldown_ms: config.alerting.cooldownMs,
        email_configured: Boolean(config.alerting.email),
        enabled:
          config.alerting.lowBalanceThresholdXlm !== undefined &&
          alertService.isEnabled() &&
          Boolean(config.horizonUrl),
        slack_5xx_enabled: slackNotifier.isEnabled("server_error"),
        slack_configured: slackNotifier.isConfigured(),
        slack_failed_transaction_enabled:
          slackNotifier.isEnabled("failed_transaction"),
        slack_low_balance_enabled: slackNotifier.isEnabled("low_balance"),
        slack_server_lifecycle_enabled:
          slackNotifier.isEnabled("server_lifecycle"),
        threshold_xlm: config.alerting.lowBalanceThresholdXlm ?? null,
      },
      total: signers.length,
    });
  } catch (error) {
    next(error);
  }
});

app.post(
  "/fee-bump",
  apiKeyMiddleware,
  apiKeyRateLimit,
  limiter,
  (req: Request, res: Response, next: NextFunction) => {
    void feeBumpHandler(req, res, next, config);
  },
);

app.post(
  "/fee-bump/batch",
  apiKeyMiddleware,
  apiKeyRateLimit,
  limiter,
  (req: Request, res: Response, next: NextFunction) => {
    void feeBumpBatchHandler(req, res, next, config);
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
  res.json({ transactions: transactionStore.getAllTransactions() });
});

app.post(
  "/test/alerts/low-balance",
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!alertService.isEnabled()) {
        res.status(400).json({
          error:
            "No alert transport configured. Set Slack webhook or SMTP env vars first.",
        });
        return;
      }

      await alertService.sendTestAlert(config);
      res.json({ message: "Test low-balance alert sent" });
    } catch (error) {
      next(error);
    }
  },
);

app.get("/admin/api-keys", listApiKeysHandler);
app.post("/admin/api-keys", upsertApiKeyHandler);
app.patch("/admin/api-keys/:key/revoke", revokeApiKeyHandler);
app.delete("/admin/api-keys/:key", revokeApiKeyHandler);
app.get("/admin/signers", listSignersHandler(config));
app.post("/admin/signers", addSignerHandler(config));
app.delete("/admin/signers/:publicKey", removeSignerHandler(config));

app.post(
  "/stripe/webhook",
  express.raw({ type: "application/json" }),
  stripeWebhookHandler,
);
app.post("/create-checkout-session", createCheckoutSessionHandler);

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

async function bootstrap(): Promise<void> {
  try {
    await hydratePersistedSigners(config);
  } catch (error) {
    logger.error(
      { ...serializeError(error) },
      "Failed to hydrate persisted signers",
    );
  }

  if (config.horizonUrls.length > 0) {
    try {
      initializeHorizonFailoverClient(config);
      ledgerMonitor = initializeLedgerMonitor(config, slackNotifier);
      ledgerMonitor.start();
      logger.info("Ledger monitor worker started");
    } catch (error) {
      logger.error(
        { ...serializeError(error) },
        "Failed to start ledger monitor",
      );
    }
  } else {
    logger.info("No Horizon URLs configured; ledger monitor disabled");
  }

  if (
    config.horizonUrl &&
    config.alerting.lowBalanceThresholdXlm !== undefined &&
    alertService.isEnabled()
  ) {
    try {
      balanceMonitor = initializeBalanceMonitor(config, alertService);
      balanceMonitor.start();
      logger.info("Balance monitor worker started");
    } catch (error) {
      logger.error(
        { ...serializeError(error) },
        "Failed to start balance monitor",
      );
    }
  } else {
    logger.info(
      "Low balance alerting disabled - missing Horizon URL, threshold, or alert transport",
    );
  }

  process.on("SIGINT", () => {
    void shutdown("SIGINT");
  });
  process.on("SIGTERM", () => {
    void shutdown("SIGTERM");
  });

  server = app.listen(PORT, () => {
    logger.info(
      {
        fee_payer_public_keys: config.feePayerAccounts.map(
          (account) => account.publicKey,
        ),
        fee_payers_loaded: config.feePayerAccounts.length,
        horizon_node_count: config.horizonUrls.length,
        horizon_nodes: config.horizonUrls,
        horizon_selection_strategy: config.horizonSelectionStrategy,
        port: PORT,
        url: `http://0.0.0.0:${PORT}`,
      },
      "Fluid server started",
    );

    void slackNotifier.notifyServerLifecycle({
      detail: `Listening on http://0.0.0.0:${PORT}`,
      phase: "start",
      timestamp: new Date(),
    });
  });
}

void bootstrap();
