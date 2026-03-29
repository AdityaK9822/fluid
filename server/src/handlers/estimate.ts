import { NextFunction, Request, Response } from "express";
import { z } from "zod";
import { Config } from "../config";
import { estimateFeeFromDescription } from "../services/feeEstimator";

const EstimateSchema = z.object({
  description: z.string().min(5).max(2000),
});

export function estimateFeeHandler(config: Config) {
  return async function handleEstimate(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const parsed = EstimateSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: "description is required and must be between 5 and 2000 characters",
        });
        return;
      }

      const estimate = await estimateFeeFromDescription(
        parsed.data.description,
        config
      );

      res.json(estimate);
    } catch (error) {
      next(error);
    }
  };
}
