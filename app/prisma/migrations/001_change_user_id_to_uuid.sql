-- AlterTable
ALTER TABLE "oauth_users" DROP COLUMN "id",
ADD COLUMN "id" UUID NOT NULL DEFAULT gen_random_uuid(),
ADD PRIMARY KEY ("id");

-- AlterColumn
ALTER TABLE "refresh_tokens" ALTER COLUMN "user_id" TYPE UUID USING (user_id::uuid);
