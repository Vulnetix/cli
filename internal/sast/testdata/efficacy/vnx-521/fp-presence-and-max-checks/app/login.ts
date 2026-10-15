export const loginSchema = z.object({
  password: z.string().min(1, "Password is required"),
});
const tooLong = password.length > 4096;
