#include <stdio.h>

int read_values(FILE *fp) {
    int count;
    long total = 0;
    double ratio;
    char grade;
~>    scanf("%d", count);
~>    fscanf(fp, "%ld %lf", total, &ratio);
~>    scanf(" %c", grade);
    return count;
}
