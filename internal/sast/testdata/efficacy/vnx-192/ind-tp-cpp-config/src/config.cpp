#include <cstdint>
#include <cstdlib>
#include <string>

struct Limits {
	std::int16_t retries;
	std::uint32_t max_body;
};

Limits load_limits()
{
	const char *r = std::getenv("APP_RETRIES");
	const char *b = std::getenv("APP_MAX_BODY");
	Limits l{};
~>	int16_t retries = std::atoi(r ? r : "3");
~>	uint32_t max_body = std::strtol(b ? b : "1048576", nullptr, 10);
	l.retries = retries;
	l.max_body = max_body;
	return l;
}
