import React, { useEffect } from 'react';

export function AfterLogin({ search }) {
  useEffect(() => {
    const next = new URLSearchParams(search).get('next') || '/';
    if (next.indexOf('acme.example.com') !== -1) {
~>      window.location.href = next;
    }
  }, [search]);
  return null;
}
