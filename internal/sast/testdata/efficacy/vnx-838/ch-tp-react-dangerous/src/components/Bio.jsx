import React from 'react';

export default function Bio({ bio }) {
~>  return <div className="bio" dangerouslySetInnerHTML={{ __html: encodeURIComponent(bio) }} />;
}
