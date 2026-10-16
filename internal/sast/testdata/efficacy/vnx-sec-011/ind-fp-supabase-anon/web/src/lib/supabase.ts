import { createClient } from '@supabase/supabase-js';

// Public anon key: safe to ship, row level security does the gating.
const SUPABASE_URL = 'https://abcdefghijklmnop.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3AiLCJyb2xlIjoiYW5vbiIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMDAwfQ.jeTosm3YP6LMfSoHPj4LsZcFvItqSUIv3DvaRjX1Myw';

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
