#include <stdlib.h>
#include <string.h>
#include "unity.h"
#include "auth.h"

void test_authenticate_rejects_bad_password(void)
{
    char *password = strdup("wrong");
    TEST_ASSERT_EQUAL(-1, check_credentials("alice", password));
    free(password);
}
