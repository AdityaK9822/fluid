import { Request, Response, NextFunction } from "express";
import { createCheckoutSession, stripe, TOP_UP_TIERS } from "../services/stripe";
import { AppError } from "../errors/AppError";
import prisma from "../utils/db";

export async function createCheckoutSessionHandler(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const { tenantId, amountCents } = req.body as {
      tenantId?: string;
      amountCents?: number;
    };

    if (!tenantId || !amountCents) {
      return next(new AppError("tenantId and amountCents are required", 400, "VALIDATION_ERROR"));
    }

    if (!TOP_UP_TIERS[amountCents]) {
      return next(
        new AppError(
          `Invalid amount. Valid options: ${Object.keys(TOP_UP_TIERS).join(", ")} cents`,
          400,
          "VALIDATION_ERROR",
        ),
      );
    }

    const origin = req.headers.origin || `${req.protocol}://${req.headers.host}`;
    const url = await createCheckoutSession(
      tenantId,
      amountCents,
      `${origin}/admin/dashboard?topup=success`,
      `${origin}/admin/dashboard?topup=cancelled`,
    );

    res.json({ url });
  } catch (err) {
    next(err);
  }
}

export async function stripeWebhookHandler(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const sig = req.headers["stripe-signature"] as string;
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!webhookSecret) {
    return next(new AppError("Stripe webhook secret not configured", 500, "CONFIG_ERROR"));
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body as Buffer, sig, webhookSecret);
  } catch (err: any) {
    return next(new AppError(`Webhook signature verification failed: ${err.message}`, 400, "VALIDATION_ERROR"));
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object as any;
    const { tenantId, amountCents } = session.metadata as {
      tenantId: string;
      amountCents: string;
    };

    const { TOP_UP_TIERS: tiers } = await import("../services/stripe");
    const tier = tiers[Number(amountCents)];

    if (tier) {
      try {
        await (prisma as any).quotaTopUp.upsert({
          where: { stripeSessionId: session.id },
          update: { status: "fulfilled" },
          create: {
            tenantId,
            stripeSessionId: session.id,
            amountCents: Number(amountCents),
            quotaStroops: BigInt(tier.quotaStroops),
            status: "fulfilled",
          },
        });

        // Increment the tenant's daily quota in the ApiKey records
        await (prisma as any).apiKey.updateMany({
          where: { tenantId, active: true },
          data: { dailyQuotaStroops: { increment: tier.quotaStroops } },
        });
      } catch (err) {
        // Log but don't fail — Stripe will retry
        console.error("Failed to fulfill quota top-up:", err);
      }
    }
  }

  res.json({ received: true });
}
