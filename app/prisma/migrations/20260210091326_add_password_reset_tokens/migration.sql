-- AlterTable
ALTER TABLE "programari" ALTER COLUMN "data_programare" SET DATA TYPE TIMESTAMPTZ(6);

-- AlterTable
ALTER TABLE "sessions" ALTER COLUMN "expires_at" SET DATA TYPE TIMESTAMPTZ(6),
ALTER COLUMN "created_at" SET DATA TYPE TIMESTAMPTZ(6);

-- CreateTable
CREATE TABLE "specialitati" (
    "id" SERIAL NOT NULL,
    "nume" VARCHAR(100) NOT NULL,
    "descriere" TEXT,
    "created_at" TIMESTAMPTZ(6) DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "specialitati_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "medic_info" (
    "id" SERIAL NOT NULL,
    "nume" VARCHAR(100) NOT NULL,
    "prenume" VARCHAR(100) NOT NULL,
    "experienta" INTEGER NOT NULL,
    "specialitate_id" INTEGER NOT NULL,
    "created_at" TIMESTAMPTZ(6) DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "medic_info_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "program_lucru" (
    "id" SERIAL NOT NULL,
    "medic_info_id" INTEGER NOT NULL,
    "ora_inceput" TIMESTAMPTZ(6),
    "ora_sfarsit" TIMESTAMPTZ(6),
    "activ" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMPTZ(6) DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "program_lucru_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "password_reset_tokens" (
    "id" TEXT NOT NULL,
    "email" VARCHAR(255) NOT NULL,
    "token" VARCHAR(255) NOT NULL,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "used" BOOLEAN NOT NULL DEFAULT false,
    "user_type" VARCHAR(20) NOT NULL,

    CONSTRAINT "password_reset_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "password_reset_tokens_token_key" ON "password_reset_tokens"("token");

-- AddForeignKey
ALTER TABLE "medic_info" ADD CONSTRAINT "medic_info_specialitate_id_fkey" FOREIGN KEY ("specialitate_id") REFERENCES "specialitati"("id") ON DELETE CASCADE ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE "program_lucru" ADD CONSTRAINT "program_lucru_medic_info_id_fkey" FOREIGN KEY ("medic_info_id") REFERENCES "medic_info"("id") ON DELETE CASCADE ON UPDATE NO ACTION;
