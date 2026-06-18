import { PrismaClient } from "@prisma/client";

// Єдиний екземпляр Prisma-клієнта на процес.
export const prisma = new PrismaClient();

export async function disconnect(): Promise<void> {
  await prisma.$disconnect();
}
