import React, { useState } from 'react';

export default function Unlock({ onUnlock }) {
  const [pin, setPin] = useState('');
  const submit = () => {
~>    if (pin == '4821') {
      onUnlock();
    }
  };
  return <input value={pin} onChange={(e) => setPin(e.target.value)} onBlur={submit} />;
}
