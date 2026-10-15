class Shape { public: virtual ~Shape() = default; };
class Circle : public Shape { public: double r = 0; };

// Circle *c = static_cast<Circle *>(s);  unchecked downcast, removed
/* const struct sockaddr_in *sin = (const struct sockaddr_in *)sa; */
const char *kHelp = "static_cast<Circle *>(s) is unchecked";
const char *kHelp2 = "(struct sockaddr_in *)sa without sa_family";
