void Session::close() {
    Request req;
    char scratch[256];
    handle(req, scratch);
~>    delete &req;
~>    delete[] scratch;
}
