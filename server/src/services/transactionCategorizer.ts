export type TransactionCategory =
  | "Token Transfer"
  | "NFT Mint"
  | "DEX Swap"
  | "Soroban Contract"
  | "Account Funding"
  | "Account Configuration"
  | "Trustline Management"
  | "Other";

const DEX_OPERATION_TYPES = new Set([
  "pathPaymentStrictReceive",
  "pathPaymentStrictSend",
  "manageBuyOffer",
  "manageSellOffer",
  "createPassiveSellOffer",
  "liquidityPoolDeposit",
  "liquidityPoolWithdraw",
  "clawback",
]);

const TRUSTLINE_OPERATION_TYPES = new Set([
  "changeTrust",
  "allowTrust",
  "setTrustLineFlags",
]);

const TOKEN_TRANSFER_OPERATION_TYPES = new Set([
  "payment",
  "createClaimableBalance",
  "claimClaimableBalance",
]);

function hasType(operationTypes: string[], expected: string): boolean {
  return operationTypes.includes(expected);
}

function includesAny(operationTypes: string[], candidates: Set<string>): boolean {
  return operationTypes.some((type) => candidates.has(type));
}

function detectNftMint(operationTypes: string[], operations: unknown[]): boolean {
  if (!hasType(operationTypes, "invokeHostFunction")) {
    return false;
  }

  // Best-effort rule for contract calls with NFT semantics in payload fields.
  return operations.some((operation) => {
    if (!operation || typeof operation !== "object") {
      return false;
    }

    const value = JSON.stringify(operation).toLowerCase();
    return value.includes("nft") && value.includes("mint");
  });
}

export function classifyTransactionCategory(
  operations: Array<{ type?: string }>
): TransactionCategory {
  if (!Array.isArray(operations) || operations.length === 0) {
    return "Other";
  }

  const operationTypes = operations
    .map((operation) => operation.type)
    .filter((type): type is string => typeof type === "string");

  if (operationTypes.length === 0) {
    return "Other";
  }

  if (detectNftMint(operationTypes, operations)) {
    return "NFT Mint";
  }

  if (includesAny(operationTypes, DEX_OPERATION_TYPES)) {
    return "DEX Swap";
  }

  if (hasType(operationTypes, "invokeHostFunction")) {
    return "Soroban Contract";
  }

  if (includesAny(operationTypes, TOKEN_TRANSFER_OPERATION_TYPES)) {
    return "Token Transfer";
  }

  if (includesAny(operationTypes, TRUSTLINE_OPERATION_TYPES)) {
    return "Trustline Management";
  }

  if (hasType(operationTypes, "createAccount")) {
    return "Account Funding";
  }

  if (hasType(operationTypes, "setOptions") || hasType(operationTypes, "manageData")) {
    return "Account Configuration";
  }

  return "Other";
}
