#include <random>
#include <vector>
#include <algorithm>
#include "LoadBalancer.h"

void LoadBalancer::rebalance()
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(backends_.begin(), backends_.end(), gen);
}

Backend &LoadBalancer::pickBackend()
{
    std::uniform_int_distribution<size_t> pick(0, backends_.size() - 1);
    size_t index = pick(rng_);
    return backends_[index];
}

void LoadBalancer::fillNonce(unsigned char *nonce, size_t n)
{
    std::random_device rd;
    std::uniform_int_distribution<int> byte(0, 255);
    for (size_t i = 0; i < n; ++i)
        nonce[i] = static_cast<unsigned char>(byte(rd));
}
