import { useEffect } from 'react';

export function Modal({ onClose, children }: { onClose: () => void; children: React.ReactNode }) {
  useEffect(() => {
    // TODO: handle the escape key on nested modals
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  /* FIXME: text overflow on narrow screens */
  return <div className="modal">{children}</div>;
}
