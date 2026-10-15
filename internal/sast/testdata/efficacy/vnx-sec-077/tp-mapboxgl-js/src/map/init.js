import mapboxgl from 'mapbox-gl';

~>mapboxgl.accessToken = 'pk.eyJ@@sample:[A-Za-z0-9_-]{60}@@.@@sample:[A-Za-z0-9_-]{22}@@';
export const map = new mapboxgl.Map({ container: 'map' });
