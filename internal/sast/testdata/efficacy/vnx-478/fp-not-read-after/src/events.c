#include <stdio.h>

void handle(int ev)
{
    int handled;
    switch (ev) {
    case 1:
        handled = 1;
        puts("one");
        break;
    case 2:
        puts("two");
        break;
    }
    puts("done");
}

void log_level(int lvl)
{
    switch (lvl) {
    case 0: puts("debug"); break;
    case 1: puts("info"); break;
    }
}
