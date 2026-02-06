import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

prisma.users.findMany({ where: { role: 'medic' } }).then(medics => { 
  console.log('Medics in auth-server:', medics.length); 
  medics.forEach(m => console.log('  -', m.email, m.role)); 
});
