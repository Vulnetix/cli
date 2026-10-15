#include <string>

int Parser::next_token(std::string &out)
{
    int c;
  again:
    c = this->getc();
    if (c == ' ' || c == '\t') {
~>        goto   again ;
    }
    if (c == '#') { skip_line(); goto again; }
    out.push_back(static_cast<char>(c));
    return c;
}
