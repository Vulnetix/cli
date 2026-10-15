import yaml from 'js-yaml';
import { NextResponse } from 'next/server';

export async function POST(request: Request) {
  const text = await request.text();
~>  const doc = yaml.load(text);
  return NextResponse.json(doc);
}
