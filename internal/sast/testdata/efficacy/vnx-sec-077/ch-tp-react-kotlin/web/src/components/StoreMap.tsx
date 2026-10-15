import Map from 'react-map-gl';

export function StoreMap() {
  return (
    <Map
~>      mapboxAccessToken="@@sample:pk\.eyJ1Ijoi[A-Za-z0-9]{12}IiwiYSI6I[A-Za-z0-9_-]{30}In0\.[A-Za-z0-9_-]{22}@@"
      mapStyle="mapbox://styles/mapbox/streets-v12"
    />
  );
}
