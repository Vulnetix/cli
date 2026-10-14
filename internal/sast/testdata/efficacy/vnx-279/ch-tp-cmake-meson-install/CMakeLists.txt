cmake_minimum_required(VERSION 3.16)
project(helper C)

add_executable(helper helper.c)

~>install(TARGETS helper DESTINATION bin PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE SETUID)
install(PROGRAMS tools/report.sh
        DESTINATION libexec/helper
        PERMISSIONS OWNER_READ OWNER_EXECUTE
~>                    SETUID)
