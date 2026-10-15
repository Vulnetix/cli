#pragma once

namespace media {
namespace detail {

~>    class Decoder {
    public:
        virtual bool decode(const char* data, int len) = 0;
        virtual
        void reset();
    };

}  // namespace detail
}  // namespace media
