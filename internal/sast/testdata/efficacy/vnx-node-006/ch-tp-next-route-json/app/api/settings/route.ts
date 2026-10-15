import { merge } from "lodash";
import { NextResponse } from "next/server";
import { loadSettings, saveSettings } from "@/lib/settings";

export async function PATCH(request: Request) {
  const patch = await request.json();
  const current = await loadSettings();
~>  const next = merge(current, patch);
  await saveSettings(next);
  return NextResponse.json(next);
}
