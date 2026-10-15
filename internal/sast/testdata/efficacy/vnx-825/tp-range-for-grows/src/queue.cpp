#include <vector>

struct job { int id; bool retry; };

void requeue(std::vector<job> &jobs)
{
    for (auto &j : jobs) {
        if (j.retry) {
~>            jobs.push_back(job{j.id + 1000, false});
        }
    }
}
