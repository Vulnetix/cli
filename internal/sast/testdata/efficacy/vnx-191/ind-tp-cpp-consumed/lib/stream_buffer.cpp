#include <cstddef>
#include <cstring>
#include <vector>

namespace io {

class StreamBuffer {
public:
	void drain(const char *data, size_t len, size_t consumed, std::vector<char> &rest)
	{
~>		len -= consumed;
		rest.resize(64 * 1024);
		std::memcpy(rest.data(), data + consumed, len);
	}
};

} // namespace io
