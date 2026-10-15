export function onReset(form) {
  form.dirty = false;
~>  form.errors === [];
  for (const f of form.fields) {
~>    f.value == "";
  }
}
