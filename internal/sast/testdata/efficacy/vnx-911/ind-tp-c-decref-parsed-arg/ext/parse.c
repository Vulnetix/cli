#include <Python.h>

static PyObject *eat(PyObject *self, PyObject *args)
{
    PyObject *obj;
    if (!PyArg_ParseTuple(args, "O", &obj))
        return NULL;
    use(obj);
~>    Py_DECREF(obj);
    Py_RETURN_NONE;
}
