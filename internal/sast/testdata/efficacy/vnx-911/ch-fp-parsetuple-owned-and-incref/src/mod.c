#include <Python.h>

static PyObject *
describe(PyObject *self, PyObject *args)
{
    PyObject *obj;
    if (!PyArg_ParseTuple(args, "O:describe", &obj))
        return NULL;
    Py_INCREF(obj);
    PyObject *r = PyObject_Repr(obj);
    Py_DECREF(obj);
    return r;
}

static PyObject *
length(PyObject *self, PyObject *args)
{
    PyObject *seq;
    if (!PyArg_ParseTuple(args, "O", &seq))
        return NULL;
    seq = PySequence_Fast(seq, "expected a sequence");
    if (seq == NULL)
        return NULL;
    Py_ssize_t n = PySequence_Fast_GET_SIZE(seq);
    Py_DECREF(seq);
    return PyLong_FromSsize_t(n);
}
