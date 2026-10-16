#include <Python.h>

static PyObject *ok_none(PyObject *self, PyObject *args)
{
    Py_RETURN_NONE;
}

static PyObject *keep(PyObject *list)
{
    PyObject *item = PyList_GetItem(list, 0);
    Py_INCREF(item);
    use(item);
    Py_DECREF(item);
    PyObject *s = PyObject_Str(item);
    Py_DECREF(s);
    Py_INCREF(Py_None);
    return Py_None;
}
