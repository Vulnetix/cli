#include <Python.h>

static PyObject *
describe(PyObject *self, PyObject *args)
{
    PyObject *obj;
    PyObject *fmt = NULL;
    if (!PyArg_ParseTuple(args, "O|O:describe",
                          &obj, &fmt))
        return NULL;
    PyObject *r = PyObject_Repr(obj);
~>    Py_DECREF(obj);
    return r;
}
