#include <string>
#include <vector>

void UploadHandler::onHeaders(const Request &req)
{
    auto length = std::stoul(req.header("Content-Length"));
~>    buffer_.resize(length);
    unsigned long count = strtoul(req.param("items").c_str(), nullptr, 10);
~>    std::vector<Item> items(count);
    process(items);
}
