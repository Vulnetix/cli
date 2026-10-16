import React from 'react';

export default function Toolbar({ user, onDelete }) {
  if (user.isAdmin) {
    return <button onClick={onDelete}>Delete</button>;
  }
  return user.role === 'editor' ? <span>Editor</span> : null;
}
