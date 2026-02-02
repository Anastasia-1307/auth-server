const { generateKeyPairSync, randomUUID } = require("crypto");
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

async function generateAndSaveKey() {
    try {
        console.log("🔑 Generare chei RSA...");
        
        // 1️⃣ Generăm perechea RSA
        const { publicKey, privateKey } = generateKeyPairSync("rsa", {
            modulusLength: 2048,
            publicKeyEncoding: { type: "spki", format: "pem" },
            privateKeyEncoding: { type: "pkcs8", format: "pem" },
        });

        const kid = randomUUID();

        // 2️⃣ Dezactivăm cheile vechi
        await prisma.auth_keys.updateMany({
            where: { is_active: true },
            data: { is_active: false },
        });

        // 3️⃣ Salvăm cheia nouă
        await prisma.auth_keys.create({
            data: {
                kid,
                public_key: publicKey,
                private_key: privateKey,
                algorithm: "RS256",
                is_active: true,
            },
        });

        console.log("✅ Cheia RSA a fost salvată cu succes");
        console.log("KID:", kid);
        console.log("🚀 Acum poți reactiva token generation!");
    } catch (error) {
        console.error("❌ Eroare la generare/salvare cheie:", error);
    } finally {
        await prisma.$disconnect();
    }
}

generateAndSaveKey();
