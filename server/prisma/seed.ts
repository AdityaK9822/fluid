import "dotenv/config";

import { createLogger, serializeError } from "../src/utils/logger";

import { PrismaBetterSqlite3 } from "@prisma/adapter-better-sqlite3";
import { PrismaClient } from "@prisma/client";

const dbUrl = process.env["DATABASE_URL"] ?? "file:./dev.db";
const adapter = new PrismaBetterSqlite3({ url: dbUrl });
const prisma = new PrismaClient({ adapter });
const logger = createLogger({ component: "prisma_seed" });

async function main () {
  logger.info("Seeding database with initial data");

  // Create test tenants with API keys
  const tenants = await Promise.all([
    prisma.tenant.upsert({
      where: { apiKey: "test-api-key-001" },
      update: {},
      create: {
        name: "Test Tenant 1",
        apiKey: "test-api-key-001",
      },
    }),
    prisma.tenant.upsert({
      where: { apiKey: "test-api-key-002" },
      update: {},
      create: {
        name: "Development Tenant",
        apiKey: "test-api-key-002",
      },
    }),
  ]);

  logger.info(
    {
      tenant_count: tenants.length,
      tenants: tenants.map((tenant) => ({ api_key: tenant.apiKey, name: tenant.name })),
    },
    "Seeded test tenants"
  );

  logger.info("Seeding complete");
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    logger.error({ ...serializeError(e) }, "Seeding failed");
    await prisma.$disconnect();
    process.exit(1);
  });
