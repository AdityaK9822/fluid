export interface TransactionRecord {
  hash: string;
  tenantId: string;
  status: 'pending' | 'submitted' | 'success' | 'failed';
  createdAt: Date;
  updatedAt: Date;
}

import { createLogger } from "../utils/logger";

const logger = createLogger({ component: "transaction_store" });

// Simple in-memory storage for transactions
// In production, this should be replaced with a proper database
class TransactionStore {
  private transactions: Map<string, TransactionRecord> = new Map();

  addTransaction (hash: string, tenantId: string, status: 'pending' | 'submitted'): void {
    const record: TransactionRecord = {
      hash,
      tenantId,
      status,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.transactions.set(hash, record);
    logger.info({ tx_hash: hash, tenant_id: tenantId, status }, "Tracked transaction");
  }

  updateTransactionStatus (hash: string, status: 'success' | 'failed'): void {
    const record = this.transactions.get(hash);
    if (record) {
      record.status = status;
      record.updatedAt = new Date();
      logger.info({ tx_hash: hash, tenant_id: record.tenantId, status }, "Updated transaction status");
    } else {
      logger.warn({ tx_hash: hash, status }, "Transaction not found for status update");
    }
  }

  getPendingTransactions (): TransactionRecord[] {
    const pending = Array.from(this.transactions.values())
      .filter(tx => tx.status === 'pending' || tx.status === 'submitted');
    logger.debug({ count: pending.length }, "Loaded pending transactions");
    return pending;
  }

  getTransaction (hash: string): TransactionRecord | undefined {
    return this.transactions.get(hash);
  }

  getAllTransactions (): TransactionRecord[] {
    return Array.from(this.transactions.values());
  }
}

export const transactionStore = new TransactionStore();
