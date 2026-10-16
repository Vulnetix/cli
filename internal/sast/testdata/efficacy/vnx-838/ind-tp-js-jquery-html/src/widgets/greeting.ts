export function show(name: string) {
~>  $('#banner').html(`<span class="hello">Hi ${encodeURIComponent(name)}</span>`);
}
