const Δt = 0.016;
const μs = 1e-6;
const label = 'Resistance in Ω';
const piLabel = 'π ≈ 3.14159';
export function step(x, v) { return x + v * Δt; }
