import React from 'react';

export function Comment({ text }: { text: string }) {
~>  const safe = text.replace(/&/i, '&#38;').replace(/'/, '&#39;');
  return <div dangerouslySetInnerHTML={{ __html: safe }} />;
}
