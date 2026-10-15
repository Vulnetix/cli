const ALLOWED_ORIGINS = ["https://app.example.com", "https://admin.example.com"];

export function originAllowed(origin: string | undefined): boolean {
  if (!origin) return false;
  if (ALLOWED_ORIGINS.indexOf(origin) !== -1) return true;
  const host = new URL(origin).hostname;
  return host === "example.com" || host.endsWith(".example.com");
}

export function isSecure(origin: string): boolean {
  return origin.startsWith("https://");
}
