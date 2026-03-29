import { describe, expect, it } from "vitest";
import { classifyTransactionCategory } from "./transactionCategorizer";

describe("classifyTransactionCategory", () => {
  it("classifies payment flows as Token Transfer", () => {
    const category = classifyTransactionCategory([{ type: "payment" }]);
    expect(category).toBe("Token Transfer");
  });

  it("classifies offer/path operations as DEX Swap", () => {
    const category = classifyTransactionCategory([{ type: "pathPaymentStrictSend" }]);
    expect(category).toBe("DEX Swap");
  });

  it("classifies invokeHostFunction NFT payloads as NFT Mint", () => {
    const category = classifyTransactionCategory([
      {
        type: "invokeHostFunction",
        function: "mint_nft",
        contract: "nft-collection",
      } as any,
    ]);
    expect(category).toBe("NFT Mint");
  });

  it("classifies invokeHostFunction calls as Soroban Contract when no NFT signal", () => {
    const category = classifyTransactionCategory([
      {
        type: "invokeHostFunction",
        function: "swap",
      } as any,
    ]);
    expect(category).toBe("Soroban Contract");
  });

  it("falls back to Other for unknown operation types", () => {
    const category = classifyTransactionCategory([{ type: "bumpSequence" }]);
    expect(category).toBe("Other");
  });
});
