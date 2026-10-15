/* Wrong: setuid(pw->pw_uid); setgid(pw->pw_gid); the gid change then fails. */
// setuid(uid) before setgid(gid) is the bug this file documents
static const char *msg = "call setuid(uid) only after setgid(gid)";
