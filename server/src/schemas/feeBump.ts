import { z } from "zod";

export const FeeBumpSchema = z.object({
  xdr: z.string().min(1, "xdr field is required and must be a non-empty string"),
  submit: z.boolean().optional(),
  token: z.string().optional(),
}).strict();

export type FeeBumpRequest = z.infer<typeof FeeBumpSchema>;
