-- DropForeignKey
ALTER TABLE "refresh_tokens" DROP CONSTRAINT "refresh_tokens_user_id_fkey";

-- AlterTable
ALTER TABLE "refresh_tokens" ADD COLUMN     "oauth_user_id" UUID;

-- CreateIndex
CREATE INDEX "idx_rt_oauth_user" ON "refresh_tokens"("oauth_user_id");

-- AddForeignKey
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_oauth_user_id_fkey" FOREIGN KEY ("oauth_user_id") REFERENCES "oauth_users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
