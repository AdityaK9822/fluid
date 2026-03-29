import { Config } from "../config";
import { priceService } from "./priceService";
import { getFeeManager } from "./feeManager";

interface EstimatorModelResponse {
  operationCount?: number;
  operationTypes?: string[];
  sorobanResourceFeeStroops?: number;
  notes?: string;
}

export interface FeeEstimate {
  confidence: "high" | "medium";
  estimatedStroops: number;
  estimatedUsd: number;
  estimatedXlm: number;
  multiplierUsed: number;
  notes: string;
  operationCount: number;
  operationTypes: string[];
  source: "openai" | "fallback";
  sorobanResourceFeeStroops: number;
}

function parsePositiveInt(value: unknown, fallback: number): number {
  const parsed = Number.parseInt(String(value), 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function clampOperationCount(value: number): number {
  return Math.min(100, Math.max(1, value));
}

function ruleBasedEstimate(description: string): EstimatorModelResponse {
  const normalized = description.toLowerCase();

  let operationCount = 1;
  const countMatch = normalized.match(/(\d+)\s+(accounts?|recipients?|addresses?|payments?|ops?|operations?)/i);
  if (countMatch) {
    operationCount = clampOperationCount(parsePositiveInt(countMatch[1], operationCount));
  }

  const operationTypes: string[] = [];
  if (normalized.includes("swap") || normalized.includes("dex") || normalized.includes("path payment")) {
    operationTypes.push("pathPaymentStrictSend");
  }
  if (normalized.includes("nft") || normalized.includes("mint") || normalized.includes("soroban")) {
    operationTypes.push("invokeHostFunction");
  }
  if (normalized.includes("trustline") || normalized.includes("change trust")) {
    operationTypes.push("changeTrust");
  }
  if (operationTypes.length === 0) {
    operationTypes.push("payment");
  }

  const sorobanResourceFeeStroops = operationTypes.includes("invokeHostFunction")
    ? 50_000
    : 0;

  return {
    operationCount,
    operationTypes,
    sorobanResourceFeeStroops,
    notes: "Fallback heuristic estimate",
  };
}

function parseCompletionJson(raw: string): EstimatorModelResponse | null {
  try {
    const parsed = JSON.parse(raw) as EstimatorModelResponse;
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

async function fetchOpenAiEstimate(description: string): Promise<EstimatorModelResponse | null> {
  const apiKey = process.env.OPENAI_API_KEY?.trim();
  if (!apiKey) {
    return null;
  }

  const model = process.env.OPENAI_FEE_ESTIMATOR_MODEL?.trim() || "gpt-4.1-mini";

  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model,
      temperature: 0,
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content:
            "You estimate Stellar transaction fee inputs. Return strict JSON with keys: operationCount (int), operationTypes (string[]), sorobanResourceFeeStroops (int), notes (string).",
        },
        {
          role: "user",
          content: description,
        },
      ],
    }),
    signal: AbortSignal.timeout(10_000),
  });

  if (!response.ok) {
    throw new Error(`OpenAI returned ${response.status}`);
  }

  const payload = (await response.json()) as {
    choices?: Array<{ message?: { content?: string } }>;
  };
  const content = payload.choices?.[0]?.message?.content;

  if (!content || typeof content !== "string") {
    return null;
  }

  return parseCompletionJson(content);
}

export async function estimateFeeFromDescription(
  description: string,
  config: Config
): Promise<FeeEstimate> {
  let source: FeeEstimate["source"] = "openai";
  let modelEstimate: EstimatorModelResponse | null = null;

  try {
    modelEstimate = await fetchOpenAiEstimate(description);
  } catch {
    modelEstimate = null;
  }

  if (!modelEstimate) {
    source = "fallback";
    modelEstimate = ruleBasedEstimate(description);
  }

  const operationCount = clampOperationCount(
    parsePositiveInt(modelEstimate.operationCount, 1)
  );
  const sorobanResourceFeeStroops = parsePositiveInt(
    modelEstimate.sorobanResourceFeeStroops,
    0
  );
  const operationTypes = Array.isArray(modelEstimate.operationTypes)
    ? modelEstimate.operationTypes
        .filter((type): type is string => typeof type === "string")
        .slice(0, 12)
    : [];

  const multiplier = getFeeManager()?.getMultiplier() ?? config.feeMultiplier;
  const estimatedStroops =
    Math.ceil((operationCount + 1) * config.baseFee * multiplier) +
    sorobanResourceFeeStroops;

  let xlmUsd = 0.1;
  try {
    const livePrice = await priceService.getTokenPriceUsd("XLM");
    xlmUsd = Number(livePrice.toString());
  } catch {
    // Keep stable fallback for offline/testing environments.
  }

  const estimatedXlm = estimatedStroops / 10_000_000;
  const estimatedUsd = estimatedXlm * xlmUsd;

  return {
    confidence: source === "openai" ? "high" : "medium",
    estimatedStroops,
    estimatedUsd: Number(estimatedUsd.toFixed(6)),
    estimatedXlm: Number(estimatedXlm.toFixed(7)),
    multiplierUsed: multiplier,
    notes: modelEstimate.notes ?? "Estimated from transaction description",
    operationCount,
    operationTypes,
    source,
    sorobanResourceFeeStroops,
  };
}
