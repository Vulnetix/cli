#include <stddef.h>

struct rec {
    int id;
    double score;
};

double score_at(struct rec *recs, size_t i)
{
    struct rec *r = recs;
~>    r += i * sizeof(struct rec);
    return r->score;
}
