import { generateKeyPairSync, randomUUID } from 'crypto';
import postgres from 'postgres';
import dotenv from 'dotenv';
dotenv.config();
// 1. Conexiunea la baza de date (înlocuiește cu datele tale din pgAdmin)
const sql = postgres({
    host:     process.env.DB_HOST,
    port:     Number(process.env.DB_PORT) || 5432, // Portul trebuie să fie număr
    database: process.env.DB_NAME,
    username: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
});
console.log("DB_USER:", process.env.DB_USER);
console.log("DB_PASSWORD:", process.env.DB_PASSWORD);

async function generateAndSaveKey() {
    try {
        // 2. Generăm cheile RSA
        const { publicKey, privateKey } = generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });

        const kid = randomUUID();


        await sql`
      INSERT INTO auth_keys (
        kid, 
        public_key, 
        private_key, 
        algorithm, 
        is_active
      ) VALUES (
        ${kid}, 
        ${publicKey}, 
        ${privateKey}, 
        'RS256', 
        true
      )
    `;

        console.log(`✅ Succes! Cheia cu KID: ${kid} a fost salvată în PostgreSQL.`);
        console.log("Cheia privata ", privateKey);
        console.log("Cheia publica ", publicKey);
    } catch (error) {
        console.error("❌ Eroare la salvarea în DB:", error);
    } finally {
        // Închidem conexiunea dacă nu mai avem nevoie de ea
        await sql.end();
    }
}

generateAndSaveKey();
// http://localhost:8080/realms/elysia/account
// http://172.16.48.132:8025/