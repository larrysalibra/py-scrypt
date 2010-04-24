#include <Python.h>

#include "scryptenc/scryptenc.h"

static PyObject *ScryptError;

static const char *errorCodes[] = {
    "success",
    "getrlimit or sysctl(hw.usermem) failed",
    "clock_getres or clock_gettime failed",
    "error computing derived key",
    "could not read salt from /dev/urandom",
    "error in OpenSSL",
    "malloc failed",
    "data is not a valid scrypt-encrypted block",
    "unrecognized scrypt format",
    "decrypting file would take too much memory",
    "decrypting file would take too long",
    "password is incorrect",
    "error writing output file",
    "error reading input file"
};

static PyObject *scrypt_encrypt(PyObject *self, PyObject *args) {
    PyStringObject *input, *password;
    int inputlen, passwordlen;
    int errorcode;
    double maxtime;
    uint8_t *outbuf;
    
    if (!PyArg_ParseTuple(args, "SSd", &input, &password, &maxtime)) {
        return NULL;
    }
    
    inputlen = PyString_Size((PyObject*) input);
    passwordlen = PyString_Size((PyObject*) password);
    
    outbuf = PyMem_Malloc(inputlen+129);
    errorcode = scryptenc_buf((uint8_t *) PyString_AsString((PyObject*) input), inputlen, 
                              outbuf, 
                              (uint8_t *) PyString_AsString((PyObject*) password), passwordlen,
                              0, 0, maxtime);
                              
    PyObject *value = NULL;
    if (errorcode != 0) {
        PyErr_Format(ScryptError, "%s", errorCodes[errorcode]);
        PyErr_SetNone(ScryptError);
    } else {
        value = Py_BuildValue("z#", outbuf, inputlen+128);
    }
    PyMem_Free(outbuf);
    
    return value;
}

static PyObject *scrypt_decrypt(PyObject *self, PyObject *args) {
    PyStringObject *input, *output, *password;
    int inputlen, outputlen, passwordlen;
    int errorcode;
    double maxtime;
    uint8_t *outbuf;
    
    if (!PyArg_ParseTuple(args, "SSd", &input, &password, &maxtime)) {
        return NULL;
    }
    
    inputlen = PyString_Size((PyObject*) input);
    passwordlen = PyString_Size((PyObject*) password);
    
    outbuf = PyMem_Malloc(inputlen);
    errorcode = scryptdec_buf((uint8_t *) PyString_AsString((PyObject *) input), inputlen,
                              outbuf, &outputlen,
                              (uint8_t *) PyString_AsString((PyObject *) password), passwordlen,
                              0, 0, maxtime);
    
    PyObject *value = NULL;
    if (errorcode != 0) {
        PyErr_Format(ScryptError, "%s", errorCodes[errorcode]);
    } else {
        value = Py_BuildValue("z#", outbuf, outputlen);
    }
    PyMem_Free(outbuf);
    return value;
}

static PyMethodDef ScryptMethods[] = {
    { "encrypt", scrypt_encrypt, METH_VARARGS, "encode(input, password, maxtime): str; encrypt a string" },
    { "decrypt", scrypt_decrypt, METH_VARARGS, "decode(input, password, maxtime): str; decrypt a string" },
    { NULL, NULL, 0, NULL }
};

PyMODINIT_FUNC initscrypt(void) {
    PyObject *m = Py_InitModule("scrypt", ScryptMethods);
    
    if (m == NULL) {
        return;
    }
    
    ScryptError = PyErr_NewException("scrypt.error", NULL, NULL);
    Py_INCREF(ScryptError);
    PyModule_AddObject(m, "error", ScryptError);
}