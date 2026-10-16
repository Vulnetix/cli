// do not goto again; use a loop
/*
 retry loops with
goto retry;
 are discouraged
*/
const char *msg = "goto retry;";
int f() {
retry:
    return 1;
}
