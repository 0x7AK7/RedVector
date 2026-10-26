"""Windows evidence DACLs. Only newly created application directories are secured."""
import ctypes
from ctypes import wintypes
import os
import re

def _api():
    adv=ctypes.WinDLL("advapi32",use_last_error=True)
    kernel=ctypes.WinDLL("kernel32",use_last_error=True)
    ptr=ctypes.c_void_p;dw=wintypes.DWORD;wide=wintypes.LPWSTR
    signatures=[
        (kernel.GetCurrentProcess,[],wintypes.HANDLE),
        (kernel.CloseHandle,[wintypes.HANDLE],wintypes.BOOL),
        (kernel.LocalFree,[ptr],ptr),
        (adv.OpenProcessToken,[wintypes.HANDLE,dw,ctypes.POINTER(wintypes.HANDLE)],wintypes.BOOL),
        (adv.GetTokenInformation,[wintypes.HANDLE,ctypes.c_int,ptr,dw,ctypes.POINTER(dw)],wintypes.BOOL),
        (adv.ConvertSidToStringSidW,[ptr,ctypes.POINTER(wide)],wintypes.BOOL),
        (adv.ConvertStringSecurityDescriptorToSecurityDescriptorW,[wide,dw,ctypes.POINTER(ptr),ctypes.POINTER(dw)],wintypes.BOOL),
        (adv.ConvertSecurityDescriptorToStringSecurityDescriptorW,[ptr,dw,dw,ctypes.POINTER(wide),ctypes.POINTER(dw)],wintypes.BOOL),
        (adv.GetFileSecurityW,[wide,dw,ptr,dw,ctypes.POINTER(dw)],wintypes.BOOL),
        (adv.SetFileSecurityW,[wide,dw,ptr],wintypes.BOOL)]
    for function,args,result in signatures:function.argtypes=args;function.restype=result
    return adv,kernel

def _sid(adv,kernel):
    token=wintypes.HANDLE();size=wintypes.DWORD()
    if not adv.OpenProcessToken(kernel.GetCurrentProcess(),8,ctypes.byref(token)):raise ValueError("Cannot verify Windows evidence identity.")
    try:
        adv.GetTokenInformation(token,1,None,0,ctypes.byref(size))
        data=ctypes.create_string_buffer(size.value)
        if not adv.GetTokenInformation(token,1,data,size,ctypes.byref(size)):raise ValueError("Cannot read Windows identity.")
        pointer=ctypes.cast(data,ctypes.POINTER(ctypes.c_void_p))[0]
        value=wintypes.LPWSTR()
        if not adv.ConvertSidToStringSidW(pointer,ctypes.byref(value)):raise ValueError("Cannot verify Windows SID.")
        try:return value.value
        finally:kernel.LocalFree(ctypes.cast(value,ctypes.c_void_p))
    finally:kernel.CloseHandle(token)

def secure_new_directory(path):
    adv,kernel=_api();sid=_sid(adv,kernel)
    descriptor=ctypes.c_void_p()
    text="D:P(A;OICI;FA;;;"+sid+")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(text,1,ctypes.byref(descriptor),None):
        raise ValueError("Cannot construct private evidence DACL.")
    try:
        if not adv.SetFileSecurityW(str(path),0x80000004,descriptor):raise ValueError("Cannot secure new evidence directory.")
    finally:kernel.LocalFree(descriptor)

def check_private(path):
    adv,kernel=_api();sid=_sid(adv,kernel);size=wintypes.DWORD()
    adv.GetFileSecurityW(str(path),5,None,0,ctypes.byref(size))
    data=ctypes.create_string_buffer(size.value)
    if not adv.GetFileSecurityW(str(path),5,data,size,ctypes.byref(size)):
        raise ValueError("Cannot verify Windows evidence DACL.")
    output=wintypes.LPWSTR()
    if not adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(data,1,5,ctypes.byref(output),None):
        raise ValueError("Cannot inspect Windows evidence permissions.")
    try:text=output.value
    finally:kernel.LocalFree(ctypes.cast(output,ctypes.c_void_p))
    _verify_sddl(text,sid)

def _verify_sddl(text,sid):
    owner=re.search(r"O:(.*?)(?=G:|D:|S:|$)",text)
    if owner is None or owner.group(1) not in (sid,"SY","BA"):
        raise ValueError("Evidence ownership belongs to another Windows principal.")
    entries=re.findall(r"\(([^()]*)\)",text)
    if not entries or "NO_ACCESS_CONTROL" in text:raise ValueError("Windows evidence DACL is unsafe.")
    for entry in entries:
        parts=entry.split(";")
        if len(parts)!=6:raise ValueError("Windows evidence DACL cannot be verified.")
        if parts[0] in ("D","OD","XD"):continue
        if parts[0]!="A" or parts[-1] not in (sid,"SY","BA","OW"):
            raise ValueError("Windows evidence directory grants access to another principal; no existing permissions were changed.")
