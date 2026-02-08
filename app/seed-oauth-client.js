const { PrismaClient } = require('./src/generated/prisma');

const prisma = new PrismaClient();

async function seedOAuthClient() {
  try {
    // Delete existing client if exists
    await prisma.oauth_clients.delete({
      where: { client_id: 'nextjs_client' }
    }).catch(() => {});

    // Create OAuth client
    const client = await prisma.oauth_clients.create({
      data: {
        client_id: 'nextjs_client',
        redirect_uris: [
          'http://localhost:3000/oauth/callback'
        ],
        name: 'Next.js Frontend'
      }
    });

    console.log('✅ OAuth client created:', client);
  } catch (error) {
    console.error('❌ Error creating OAuth client:', error);
  } finally {
    await prisma.$disconnect();
  }
}

seedOAuthClient();
