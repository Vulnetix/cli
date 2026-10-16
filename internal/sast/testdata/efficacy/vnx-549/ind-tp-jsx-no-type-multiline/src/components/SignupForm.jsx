import React, { useState } from 'react';

export default function SignupForm({ onSubmit }) {
  const [pw, setPw] = useState('');
  return (
    <form onSubmit={() => onSubmit(pw)}>
~>      <input
        id="new-password"
        name="newPassword"
        value={pw}
        onChange={(e) => setPw(e.target.value)}
      />
      <button type="submit">Create account</button>
    </form>
  );
}
