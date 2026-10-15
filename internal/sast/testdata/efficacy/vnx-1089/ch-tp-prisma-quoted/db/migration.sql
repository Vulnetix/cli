-- CreateTable
~>CREATE TABLE "Finding" (
    "id" TEXT NOT NULL,
    "orgId" TEXT NOT NULL,
    CONSTRAINT "Finding_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Finding_orgId_idx" ON "Finding"("orgId");
CREATE INDEX "Finding_a_idx" ON "Finding"("a");
CREATE INDEX "Finding_b_idx" ON "Finding"("b");
CREATE INDEX "Finding_c_idx" ON "Finding"("c");
CREATE INDEX "Finding_d_idx" ON "Finding"("d");
CREATE INDEX "Finding_e_idx" ON "Finding"("e");
CREATE INDEX "Finding_f_idx" ON "Finding"("f");
CREATE INDEX "Finding_g_idx" ON "Finding" USING GIN ("g");
CREATE UNIQUE INDEX "Finding_h_key" ON public."Finding"("h");
