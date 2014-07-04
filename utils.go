// Copyright 2010-2012 The W32 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package w32

import (
	"C"
	"reflect"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

func MakeIntResource(id uint16) *uint16 {
	return (*uint16)(unsafe.Pointer(uintptr(id)))
}

func LOWORD(dw uint32) uint16 {
	return uint16(dw)
}

func HIWORD(dw uint32) uint16 {
	return uint16(dw >> 16 & 0xffff)
}

func BoolToBOOL(value bool) BOOL {
	if value {
		return 1
	}

	return 0
}

func UTF16PtrToString(cstr *uint16) string {
	if cstr != nil {
		us := make([]uint16, 0, 256)
		for p := uintptr(unsafe.Pointer(cstr)); ; p += 2 {
			u := *(*uint16)(unsafe.Pointer(p))
			if u == 0 {
				return string(utf16.Decode(us))
			}
			us = append(us, u)
		}
	}

	return ""
}

func ComAddRef(unknown *IUnknown) int32 {
	ret, _, _ := syscall.Syscall(unknown.lpVtbl.pAddRef, 1,
		uintptr(unsafe.Pointer(unknown)),
		0,
		0)
	return int32(ret)
}

func ComRelease(unknown *IUnknown) int32 {
	ret, _, _ := syscall.Syscall(unknown.lpVtbl.pRelease, 1,
		uintptr(unsafe.Pointer(unknown)),
		0,
		0)
	return int32(ret)
}

func ComQueryInterface(unknown *IUnknown, id *GUID) *IDispatch {
	var disp *IDispatch
	hr, _, _ := syscall.Syscall(unknown.lpVtbl.pQueryInterface, 3,
		uintptr(unsafe.Pointer(unknown)),
		uintptr(unsafe.Pointer(id)),
		uintptr(unsafe.Pointer(&disp)))
	if hr != 0 {
		panic("Invoke QieryInterface error.")
	}
	return disp
}

func ComGetIDsOfName(disp *IDispatch, names []string) []int32 {
	wnames := make([]*uint16, len(names))
	dispid := make([]int32, len(names))
	for i := 0; i < len(names); i++ {
		wnames[i] = syscall.StringToUTF16Ptr(names[i])
	}
	hr, _, _ := syscall.Syscall6(disp.lpVtbl.pGetIDsOfNames, 6,
		uintptr(unsafe.Pointer(disp)),
		uintptr(unsafe.Pointer(IID_NULL)),
		uintptr(unsafe.Pointer(&wnames[0])),
		uintptr(len(names)),
		uintptr(GetUserDefaultLCID()),
		uintptr(unsafe.Pointer(&dispid[0])))
	if hr != 0 {
		panic("Invoke GetIDsOfName error.")
	}
	return dispid
}

func ComInvoke(disp *IDispatch, dispid int32, dispatch int16, params ...interface{}) (result *VARIANT) {
	var dispparams DISPPARAMS

	if dispatch&DISPATCH_PROPERTYPUT != 0 {
		dispnames := [1]int32{DISPID_PROPERTYPUT}
		dispparams.RgdispidNamedArgs = uintptr(unsafe.Pointer(&dispnames[0]))
		dispparams.CNamedArgs = 1
	}
	var vargs []VARIANT
	if len(params) > 0 {
		vargs = make([]VARIANT, len(params))
		for i, v := range params {
			//n := len(params)-i-1
			n := len(params) - i - 1
			VariantInit(&vargs[n])
			switch v.(type) {
			case bool:
				if v.(bool) {
					vargs[n] = VARIANT{VT_BOOL, 0, 0, 0, 0xffff}
				} else {
					vargs[n] = VARIANT{VT_BOOL, 0, 0, 0, 0}
				}
			case *bool:
				vargs[n] = VARIANT{VT_BOOL | VT_BYREF, 0, 0, 0, int64(uintptr(unsafe.Pointer(v.(*bool))))}
			case byte:
				vargs[n] = VARIANT{VT_I1, 0, 0, 0, int64(v.(byte))}
			case *byte:
				vargs[n] = VARIANT{VT_I1 | VT_BYREF, 0, 0, 0, int64(uintptr(unsafe.Pointer(v.(*byte))))}
			case int16:
				vargs[n] = VARIANT{VT_I2, 0, 0, 0, int64(v.(int16))}
			case *int16:
				vargs[n] = VARIANT{VT_I2 | VT_BYREF, 0, 0, 0, int64(uintptr(unsafe.Pointer(v.(*int16))))}
			case uint16:
				vargs[n] = VARIANT{VT_UI2, 0, 0, 0, int64(v.(int16))}
			case *uint16:
				vargs[n] = VARIANT{VT_UI2 | VT_BYREF, 0, 0, 0, int64(uintptr(unsafe.Pointer(v.(*uint16))))}
			case int, int32:
				vargs[n] = VARIANT{VT_UI4, 0, 0, 0, int64(v.(int))}
			case *int, *int32:
				vargs[n] = VARIANT{VT_I4 | VT_BYREF, 0, 0, 0, int64(uintptr(unsafe.Pointer(v.(*int))))}
			case uint, uint32:
				vargs[n] = VARIANT{VT_UI4, 0, 0, 0, int64(v.(uint))}
			case *uint, *uint32:
				vargs[n] = VARIANT{VT_UI4 | VT_BYREF, 0, 0, 0, int64(uintptr(unsafe.Pointer(v.(*uint))))}
			case int64:
				vargs[n] = VARIANT{VT_I8, 0, 0, 0, v.(int64)}
			case *int64:
				vargs[n] = VARIANT{VT_I8 | VT_BYREF, 0, 0, 0, int64(uintptr(unsafe.Pointer(v.(*int64))))}
			case uint64:
				vargs[n] = VARIANT{VT_UI8, 0, 0, 0, int64(v.(uint64))}
			case *uint64:
				vargs[n] = VARIANT{VT_UI8 | VT_BYREF, 0, 0, 0, int64(uintptr(unsafe.Pointer(v.(*uint64))))}
			case float32:
				vargs[n] = VARIANT{VT_R4, 0, 0, 0, int64(v.(float32))}
			case *float32:
				vargs[n] = VARIANT{VT_R4 | VT_BYREF, 0, 0, 0, int64(uintptr(unsafe.Pointer(v.(*float32))))}
			case float64:
				vargs[n] = VARIANT{VT_R8, 0, 0, 0, int64(v.(float64))}
			case *float64:
				vargs[n] = VARIANT{VT_R8 | VT_BYREF, 0, 0, 0, int64(uintptr(unsafe.Pointer(v.(*float64))))}
			case string:
				vargs[n] = VARIANT{VT_BSTR, 0, 0, 0, int64(uintptr(unsafe.Pointer(SysAllocString(v.(string)))))}
			case *string:
				vargs[n] = VARIANT{VT_BSTR | VT_BYREF, 0, 0, 0, int64(uintptr(unsafe.Pointer(v.(*string))))}
			case *IDispatch:
				vargs[n] = VARIANT{VT_DISPATCH, 0, 0, 0, int64(uintptr(unsafe.Pointer(v.(*IDispatch))))}
			case **IDispatch:
				vargs[n] = VARIANT{VT_DISPATCH | VT_BYREF, 0, 0, 0, int64(uintptr(unsafe.Pointer(v.(**IDispatch))))}
			case nil:
				vargs[n] = VARIANT{VT_NULL, 0, 0, 0, 0}
			case *VARIANT:
				vargs[n] = VARIANT{VT_VARIANT | VT_BYREF, 0, 0, 0, int64(uintptr(unsafe.Pointer(v.(*VARIANT))))}
			default:
				panic("unknown type")
			}
		}
		dispparams.Rgvarg = uintptr(unsafe.Pointer(&vargs[0]))
		dispparams.CArgs = uint32(len(params))
	}

	var ret VARIANT
	var excepInfo EXCEPINFO
	VariantInit(&ret)
	hr, _, _ := syscall.Syscall9(disp.lpVtbl.pInvoke, 8,
		uintptr(unsafe.Pointer(disp)),
		uintptr(dispid),
		uintptr(unsafe.Pointer(IID_NULL)),
		uintptr(GetUserDefaultLCID()),
		uintptr(dispatch),
		uintptr(unsafe.Pointer(&dispparams)),
		uintptr(unsafe.Pointer(&ret)),
		uintptr(unsafe.Pointer(&excepInfo)),
		0)
	if hr != 0 {
		if excepInfo.BstrDescription != nil {
			bs := UTF16PtrToString(excepInfo.BstrDescription)
			panic(bs)
		}
	}
	for _, varg := range vargs {
		if varg.VT == VT_BSTR && varg.Val != 0 {
			SysFreeString(((*int16)(unsafe.Pointer(uintptr(varg.Val)))))
		}
	}
	result = &ret
	return
}

func CredentialFromCREDENTIAL(cred *CREDENTIAL) (result *Credential) {
	result = new(Credential)
	result.Flags = cred.Flags
	result.Type = uint(cred.Type)
	result.TargetName = UTF16PtrToString(cred.TargetName)
	result.Comment = UTF16PtrToString(cred.Comment)
	result.LastWritten.HighDateTime = cred.LastWritten.DwHighDateTime
	result.LastWritten.LowDateTime = cred.LastWritten.DwLowDateTime
	result.CredentialBlob = C.GoBytes(unsafe.Pointer(cred.CredentialBlob), C.int(cred.CredentialBlobSize))
	result.Persist = uint(cred.Persist)
	result.Attributes = make([]CredentialAttribute, cred.AttributeCount)
	attrSliceHeader := reflect.SliceHeader{
		Data: cred.Attributes,
		Len:  int(cred.AttributeCount),
		Cap:  int(cred.AttributeCount),
	}
	attrSlice := *(*[]CREDENTIAL_ATTRIBUTE)(unsafe.Pointer(&attrSliceHeader))
	for i, attr := range attrSlice {
		resultAttr := &result.Attributes[i]
		resultAttr.Keyword = UTF16PtrToString(attr.Keyword)
		resultAttr.Flags = attr.Flags
		resultAttr.Value = C.GoBytes(unsafe.Pointer(attr.Value), C.int(attr.ValueSize))
	}
	result.TargetAlias = UTF16PtrToString(cred.TargetAlias)
	result.UserName = UTF16PtrToString(cred.UserName)

	return result
}

func CredentialToCREDENTIAL(cred *Credential) (result CREDENTIAL, attributes []*CREDENTIAL_ATTRIBUTE) {
	result.Flags = cred.Flags
	result.Type = DWORD(cred.Type)
	result.TargetName, _ = syscall.UTF16PtrFromString(cred.TargetName)
	result.Comment, _ = syscall.UTF16PtrFromString(cred.Comment)
	result.LastWritten.DwHighDateTime = cred.LastWritten.HighDateTime
	result.LastWritten.DwLowDateTime = cred.LastWritten.LowDateTime
	result.CredentialBlobSize = DWORD(len(cred.CredentialBlob))
	if result.CredentialBlobSize > 0 {
		result.CredentialBlob = (uintptr)(unsafe.Pointer(&cred.CredentialBlob[0]))
	} else {
		result.CredentialBlob = 0
	}
	result.Persist = DWORD(cred.Persist)
	result.AttributeCount = DWORD(len(cred.Attributes))
	attributes = make([]*CREDENTIAL_ATTRIBUTE, len(cred.Attributes))
	for i, attribute := range cred.Attributes {
		attributes[i] = &CREDENTIAL_ATTRIBUTE{
			Keyword: syscall.StringToUTF16Ptr(attribute.Keyword),
			Flags: attribute.Flags,
			ValueSize: DWORD(len(attribute.Value)),
			Value: 0,
		}
		if len(attribute.Value) > 0 {
			attributes[i].Value = uintptr(unsafe.Pointer(&attribute.Value[0]))
		}
	}
	if len(attributes) > 0 {
		result.Attributes = (uintptr)(unsafe.Pointer(&attributes[0]))
	} else {
		result.Attributes = 0
	}
	result.TargetAlias, _ = syscall.UTF16PtrFromString(cred.TargetAlias)
	result.UserName, _ = syscall.UTF16PtrFromString(cred.UserName)

	return result, attributes
}
