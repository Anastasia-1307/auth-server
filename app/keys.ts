import { generateKeyPairSync, randomUUID } from "crypto";
import dotenv from "dotenv";
dotenv.config();
import { PrismaClient } from './src/generated/prisma';

const prisma = new PrismaClient();

async function generateAndSaveKey() {
    try {
        // 1️⃣ Generăm perechea RSA
        const { publicKey, privateKey } = generateKeyPairSync("rsa", {
            modulusLength: 2048,
            publicKeyEncoding: { type: "spki", format: "pem" },
            privateKeyEncoding: { type: "pkcs8", format: "pem" },
        });

        const kid = randomUUID();

        // 2️⃣ (opțional, recomandat) dezactivăm cheile vechi
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
    } catch (error) {
        console.error("❌ Eroare la generare/salvare cheie:", error);
    } finally {
        await prisma.$disconnect();
    }
}

generateAndSaveKey();
// http://localhost:8080/realms/elysia/account
// http://172.16.48.132:8025/