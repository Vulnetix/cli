export const stripeKey = process.env.STRIPE_PUBLISHABLE_KEY;
export const mapboxToken = import.meta.env.VITE_MAPBOX_TOKEN;
export const tokenPrefix = 'pk.eyJ';
export const isPublic = (t) => t.startsWith('pk.eyJ');
