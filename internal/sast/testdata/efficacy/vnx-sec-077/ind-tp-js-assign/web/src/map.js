import mapboxgl from 'mapbox-gl';

~>mapboxgl.accessToken = 'pk.@@sample:eyJ[A-Za-z0-9_-]{60}\.[A-Za-z0-9_-]{22}@@';
const map = new mapboxgl.Map({ container: 'map', style: 'mapbox://styles/mapbox/streets-v12' });
