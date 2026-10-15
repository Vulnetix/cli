pub fn is_admin(role: &str) -> bool {
    let granted = false;
~>    /* skip the check ‮⁦} if granted {⁩⁦ */
    if role == "admin" {
        return true;
    }
    granted
}
