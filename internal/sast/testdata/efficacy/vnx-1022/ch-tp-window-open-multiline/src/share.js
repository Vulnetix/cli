export function openAttachment(attachment) {
~>  window.open(
    attachment.downloadUrl,
    '_blank'
  );
}

export function openResult(row) {
~>  const w = window.open(row.link, '_blank');
  w.focus();
}
