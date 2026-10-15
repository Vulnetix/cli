export function guardAdmin(): void {
~>  if (localStorage.getItem("isAdmin") === "true") {
    showAdminMenu();
  } else {
    window.location.assign("/login");
  }
}
