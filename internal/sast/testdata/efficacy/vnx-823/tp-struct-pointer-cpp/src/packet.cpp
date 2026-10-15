#include <cstdint>
#include <vector>

struct header {
    uint32_t len;
    uint32_t type;
};

const unsigned char *payload(const struct header *hdr)
{
~>    return (const unsigned char *)(hdr + sizeof(struct header));
}

int last_score(const std::vector<int> &scores)
{
    int best = 0;
~>    for (size_t k = 0; k <= scores.size(); ++k) {
        if (scores[k] > best) best = scores[k];
    }
    return best;
}
