export function greet(name: string): void {
~>  (document.getElementById('out') as HTMLElement).innerHTML = `<b>Hello ${name}</b>`;
}
