// Parses "HH:MM" opening hours; seconds are ignored on purpose.
export function toMinutes(slot) {
  const [hours, minutes] = slot.split(':');
  return Number(hours) * 60 + Number(minutes);
}

export function clock(t) {
  const [hh, mm] = t.split(":").map(Number);
  return hh * 60 + mm;
}
