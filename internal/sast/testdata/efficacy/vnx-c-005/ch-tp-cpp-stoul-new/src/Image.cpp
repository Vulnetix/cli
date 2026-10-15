#include <cstdlib>
#include <string>

void Image::load(const std::string &w, const std::string &h)
{
	unsigned width = std::stoul(w);
	unsigned height = std::stoul(h);
~>	m_pixels = static_cast<uint32_t *>(std::malloc(width * height * 4));
}
