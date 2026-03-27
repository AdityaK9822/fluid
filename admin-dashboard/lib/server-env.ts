/** Server-side environment helpers — only import from Server Components or API routes */
export const fluidServerUrl =
  process.env.FLUID_SERVER_URL?.trim() ?? "http://localhost:3000";

export const fluidAdminToken = process.env.FLUID_ADMIN_TOKEN?.trim() ?? "";
