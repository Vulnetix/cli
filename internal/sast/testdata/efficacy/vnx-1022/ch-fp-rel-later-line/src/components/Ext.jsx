export const ExternalLink = ({ to, children }) => (
  <a
    href={to}
    target="_blank"
    className="ext"
    rel="noreferrer"
  >
    {children}
  </a>
);
