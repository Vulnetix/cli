#include <map>
#include <string>

struct Settings {
    std::map<std::string, std::string> values;
    int retries = 3;
};

const Settings &default_settings()
{
    Settings defaults;
    defaults.values["region"] = "eu-west-1";
    defaults.retries = 5;
~>    return defaults;
}
