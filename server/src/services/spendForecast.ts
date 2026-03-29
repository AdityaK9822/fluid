const STROOPS_PER_XLM = 10_000_000;
const DEFAULT_LOOKBACK_DAYS = 30;
const DEFAULT_PROJECTION_DAYS = 30;

export interface SpendForecastInput {
  currentBalanceStroops: bigint;
  lookbackDays?: number;
  now?: Date;
  transactions: Array<{
    costStroops: bigint | number | string;
    createdAt: Date;
  }>;
}

export interface SpendSeriesPoint {
  date: string;
  spendXlm: number;
}

export interface BalanceSeriesPoint {
  date: string;
  balanceXlm: number;
}

export interface SpendForecastResult {
  alert: boolean;
  averageDailySpendXlm: number;
  currentBalanceXlm: number;
  historicalBalance: BalanceSeriesPoint[];
  projectedBalance: BalanceSeriesPoint[];
  runwayDays: number | null;
  spendSeries: SpendSeriesPoint[];
}

function roundTo(value: number, decimals: number): number {
  const factor = 10 ** decimals;
  return Math.round(value * factor) / factor;
}

function formatIsoDay(date: Date): string {
  return date.toISOString().split("T")[0];
}

function buildRecentDays(now: Date, dayCount: number): string[] {
  const days: string[] = [];

  for (let offset = dayCount - 1; offset >= 0; offset -= 1) {
    const value = new Date(now);
    value.setUTCDate(value.getUTCDate() - offset);
    days.push(formatIsoDay(value));
  }

  return days;
}

function toXlm(stroops: bigint | number | string): number {
  return Number(stroops) / STROOPS_PER_XLM;
}

function linearRegression(values: number[]): { intercept: number; slope: number } {
  if (values.length === 0) {
    return { intercept: 0, slope: 0 };
  }

  if (values.length === 1) {
    return { intercept: values[0], slope: 0 };
  }

  const n = values.length;
  const meanX = (n - 1) / 2;
  const meanY = values.reduce((sum, value) => sum + value, 0) / n;

  let numerator = 0;
  let denominator = 0;
  for (let index = 0; index < n; index += 1) {
    const centeredX = index - meanX;
    numerator += centeredX * (values[index] - meanY);
    denominator += centeredX * centeredX;
  }

  const slope = denominator === 0 ? 0 : numerator / denominator;
  const intercept = meanY - slope * meanX;

  return { intercept, slope };
}

function projectDailySpend(
  intercept: number,
  slope: number,
  xIndex: number
): number {
  return Math.max(0, intercept + slope * xIndex);
}

export function calculateSpendForecast(input: SpendForecastInput): SpendForecastResult {
  const now = input.now ?? new Date();
  const lookbackDays = Math.max(1, input.lookbackDays ?? DEFAULT_LOOKBACK_DAYS);
  const dayKeys = buildRecentDays(now, lookbackDays);

  const spendByDay = new Map<string, number>();
  for (const key of dayKeys) {
    spendByDay.set(key, 0);
  }

  for (const transaction of input.transactions) {
    const dayKey = formatIsoDay(transaction.createdAt);
    if (!spendByDay.has(dayKey)) {
      continue;
    }

    spendByDay.set(dayKey, (spendByDay.get(dayKey) ?? 0) + toXlm(transaction.costStroops));
  }

  const spendSeries: SpendSeriesPoint[] = dayKeys.map((date) => ({
    date,
    spendXlm: roundTo(spendByDay.get(date) ?? 0, 7),
  }));

  const spendValues = spendSeries.map((point) => point.spendXlm);
  const averageDailySpendXlm =
    spendValues.reduce((sum, value) => sum + value, 0) / Math.max(1, spendValues.length);

  const { intercept, slope } = linearRegression(spendValues);
  const latestPredictedSpend = projectDailySpend(
    intercept,
    slope,
    spendValues.length - 1
  );

  const currentBalanceXlm = Number(input.currentBalanceStroops) / STROOPS_PER_XLM;

  const historicalBalance: BalanceSeriesPoint[] = new Array(spendSeries.length);
  let rollingBalance = currentBalanceXlm;
  for (let index = spendSeries.length - 1; index >= 0; index -= 1) {
    historicalBalance[index] = {
      date: spendSeries[index].date,
      balanceXlm: roundTo(Math.max(0, rollingBalance), 7),
    };
    rollingBalance += spendSeries[index].spendXlm;
  }

  const projectedBalance: BalanceSeriesPoint[] = [];
  let projectedBalanceXlm = currentBalanceXlm;
  for (let day = 0; day <= DEFAULT_PROJECTION_DAYS; day += 1) {
    const projectedDate = new Date(now);
    projectedDate.setUTCDate(projectedDate.getUTCDate() + day);

    if (day > 0) {
      const projectedSpend = projectDailySpend(
        intercept,
        slope,
        spendValues.length - 1 + day
      );
      projectedBalanceXlm = Math.max(0, projectedBalanceXlm - projectedSpend);
    }

    projectedBalance.push({
      date: formatIsoDay(projectedDate),
      balanceXlm: roundTo(projectedBalanceXlm, 7),
    });

    if (projectedBalanceXlm <= 0) {
      break;
    }
  }

  const runwayDays =
    latestPredictedSpend > 0 ? roundTo(currentBalanceXlm / latestPredictedSpend, 1) : null;

  return {
    alert: runwayDays !== null && runwayDays < 7,
    averageDailySpendXlm: roundTo(averageDailySpendXlm, 7),
    currentBalanceXlm: roundTo(currentBalanceXlm, 7),
    historicalBalance,
    projectedBalance,
    runwayDays,
    spendSeries,
  };
}
