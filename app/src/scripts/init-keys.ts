import { generateKeyPairSync, randomUUID } from "crypto";
import { PrismaClient } from '../generated/prisma';

const prisma = new PrismaClient();

async function initializeKeys() {
    try {
        console.log("🔍 Verificăm cheile JWT existente...");
        
        // Verificăm dacă există chei active
        const existingActiveKey = await prisma.auth_keys.findFirst({
            where: { is_active: true }
        });

        if (existingActiveKey) {
            console.log("✅ Cheie JWT activă existentă găsită:", existingActiveKey.kid);
            console.log("🔑 Nu este necesară generarea unei noi chei.");
        } else {
            console.log("🔑 Nu există chei active. Generăm cheie nouă...");

            // Generăm perechea RSA
            const { publicKey, privateKey } = generateKeyPairSync("rsa", {
                modulusLength: 2048,
                publicKeyEncoding: { type: "spki", format: "pem" },
                privateKeyEncoding: { type: "pkcs8", format: "pem" },
            });

            const kid = randomUUID();

            // Salvăm cheia nouă
            await prisma.auth_keys.create({
                data: {
                    kid,
                    public_key: publicKey,
                    private_key: privateKey,
                    algorithm: "RS256",
                    is_active: true,
                },
            });

            console.log("✅ Cheie JWT generată și salvată cu succes");
            console.log("🔑 KID:", kid);
            console.log("🔐 Algoritm: RS256");
            console.log("📏 Lungime cheie: 2048 bits");
        }

        // Verificăm și creăm client OAuth dacă nu există
        console.log("🔍 Verificăm clientul OAuth existent...");
        const existingOAuthClient = await prisma.oauth_clients.findUnique({
            where: { client_id: "nextjs_client" }
        });

        if (existingOAuthClient) {
            console.log("✅ Client OAuth existent găsit:", existingOAuthClient.client_id);
            console.log("🔗 Redirect URIs:", existingOAuthClient.redirect_uris.join(", "));
        } else {
            console.log("🔑 Nu există client OAuth. Creăm client nou...");
            
            await prisma.oauth_clients.create({
                data: {
                    client_id: "nextjs_client",
                    client_secret_hash: "none",
                    redirect_uris: [
                        "http://localhost:3000/admin",
                        "http://localhost:3000/pacient", 
                        "http://localhost:3000/medic",
                        "http://localhost:3000/oauth/callback"
                    ],
                    name: "Next.js Application"
                }
            });

            console.log("✅ Client OAuth creat cu succes");
            console.log("🔑 Client ID: nextjs_client");
            console.log("🔗 Redirect URIs: http://localhost:3000/admin, http://localhost:3000/pacient, http://localhost:3000/medic, http://localhost:3000/oauth/callback");
        }
        
    } catch (error) {
        console.error("❌ Eroare la inițializarea cheilor:", error);
        throw error;
    } finally {
        await prisma.$disconnect();
    }
}

// Exportăm funcția pentru a putea fi apelată din altă parte
export { initializeKeys };

// Rulăm doar dacă scriptul este executat direct
if (require.main === module) {
    initializeKeys()
        .then(() => {
            console.log("🎉 Inițializare chei completă");
            process.exit(0);
        })
        .catch((error) => {
            console.error("💥 Inițializare eșuată:", error);
            process.exit(1);
        });
}
