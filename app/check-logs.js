import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function checkLogs() {
  try {
    const logs = await prisma.user_logs.findMany();
    console.log('User logs count:', logs.length);
    console.log('Sample logs:', logs.slice(0, 3));
    console.log('All logs:', logs);
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await prisma.$disconnect();
  }
}

checkLogs();
