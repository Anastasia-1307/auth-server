-- Generează o cheie RSA și insereaz-o în DB
-- Rulează acest SQL direct în PostgreSQL

-- Dezactivează cheile vechi
UPDATE auth_keys SET is_active = false WHERE is_active = true;

-- Inserează o cheie nouă (va fi generată de Prisma/JWT service)
-- Momentan, vom lăsa JWT service să genereze cheia la prima rulare

-- Verifică dacă există chei
SELECT COUNT(*) as key_count FROM auth_keys WHERE is_active = true;
