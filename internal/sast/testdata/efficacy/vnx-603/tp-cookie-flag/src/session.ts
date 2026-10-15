export function markLoggedIn(): void {
~>  document.cookie = "loggedIn=true; path=/";
}

export function markRole(): void {
~>  document.cookie = 'role=admin';
}
