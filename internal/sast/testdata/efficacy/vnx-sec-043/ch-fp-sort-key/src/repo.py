item = {"PK": f"USER#{uid}", "SK": f"ORDER#{order_id}"}
MA@@sample:S[K]5d41402abc4b2a76b9719d911017c592@@ = 1
cache_key = "SK" + hashlib.md5(payload).hexdigest()
digest = "@@sample:S[K]A1[B]2C[3]D4[E]5F[6]07[1]82[9]3A[4]B5[C]6D[7]E8[F]90[A]@@"
