#include <random>
#include <array>

class KeyService {
 public:
  std::array<uint8_t, 32> NewAesKey();

 private:
  std::mt19937 rng_;
};

std::array<uint8_t, 32> KeyService::NewAesKey() {
  std::uniform_int_distribution<int> byte(0, 255);
  std::array<uint8_t, 32> aes_key{};
  for (auto &b : aes_key) {
~>    b = static_cast<uint8_t>(byte(rng_));
  }
  return aes_key;
}
