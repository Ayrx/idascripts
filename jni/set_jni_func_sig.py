import idc
import ida_hexrays
import ida_typeinf


def apply_jni_func_sig():
    """ Apply the standard JNIEnv* and jobject signature to a function.
    """
    print("Function: {}".format(idc.get_func_name(here())))

    func = ida_hexrays.decompile(here())
    func_type = func.type
    funcdata = ida_typeinf.func_type_data_t()
    func_type.get_func_details(funcdata)

    jnienv = ida_typeinf.tinfo_t()
    jnienv.get_named_type(ida_typeinf.get_idati(), "JNIEnv")
    jnienv_ptr = ida_typeinf.tinfo_t()
    jnienv_ptr.create_ptr(jnienv)

    jobject = ida_typeinf.tinfo_t()
    jobject.get_named_type(ida_typeinf.get_idati(), "jobject")

    funcdata[0].type = jnienv_ptr
    funcdata[0].name = "env"
    funcdata[1].type = jobject
    funcdata[1].name = "thiz"
    new_tinfo = ida_typeinf.tinfo_t()
    new_tinfo.create_func(funcdata)
    ida_typeinf.apply_tinfo(here(), new_tinfo, ida_typeinf.TINFO_DEFINITE)
