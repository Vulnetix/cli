#include <Python.h>

static long
port_from(PyObject *cfg)
{
    PyObject *port = PyDict_GetItemString(cfg, "port");
    if (port == NULL)
        return -1;
    long v = PyLong_AsLong(port);
~>    Py_DECREF(port);
    return v;
}
