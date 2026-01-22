// Package provides stubs for the PKCS#11 ABI.
package main

// #include "cgo.h"
import "C"
import "fmt"

var functionList = C.CK_FUNCTION_LIST{}

func main() {}

//export C_CancelFunction
func C_CancelFunction(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_CloseAllSessions
func C_CloseAllSessions(slotID C.CK_SLOT_ID) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_CloseSession
func C_CloseSession(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_CopyObject
func C_CopyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, usCount C.CK_USHORT, phNewObject C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_CreateObject
func C_CreateObject(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, usCount C.CK_USHORT, phObject C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Decrypt
func C_Decrypt(hSession C.CK_SESSION_HANDLE, pEncryptedData C.CK_BYTE_PTR, usEncryptedDataLen C.CK_USHORT, pData C.CK_BYTE_PTR, pusDataLen C.CK_USHORT_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DecryptDigestUpdate

//export C_DecryptFinal
func C_DecryptFinal(hSession C.CK_SESSION_HANDLE, pLastPart C.CK_BYTE_PTR, usLastPartLen C.CK_USHORT_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DecryptInit
//export C_DecryptMessage
//export C_DecryptMessageBegin
//export C_DecryptMessageNext
//export C_DecryptUpdate
//export C_DecryptVerifyUpdate
//export C_DeriveKey
//export C_DestroyObject
//export C_Digest
//export C_DigestEncryptUpdate
//export C_DigestFinal
//export C_DigestInit
//export C_DigestKey
//export C_DigestUpdate
//export C_Encrypt
//export C_EncryptFinal
//export C_EncryptInit
//export C_EncryptMessage
//export C_EncryptMessageBegin
//export C_EncryptMessageNext
//export C_EncryptUpdate
//export C_Finalize
//export C_FindObjects
//export C_FindObjectsFinal
//export C_FindObjectsInit
//export C_GenerateKey
//export C_GenerateKeyPair
//export C_GenerateRandom
//export C_GetAttributeValue

//export C_GetFunctionList
func C_GetFunctionList(ppFunctionList C.CK_FUNCTION_LIST_PTR_PTR) C.CK_RV {
	fmt.Printf("[CALLED]: C_GetFunctionList(ppFunctionList=%+v)\n", ppFunctionList)

	if ppFunctionList == nil {
		fmt.Println(" - ppFunctionList IS NULL")
		return C.CKR_ARGUMENTS_BAD
	}

	*ppFunctionList = &functionList

	return C.CKR_OK
}

//export C_GetFunctionStatus
//export C_GetInfo
//export C_GetInterface
//export C_GetInterfaceList
//export C_GetMechanismInfo
//export C_GetMechanismList
//export C_GetObjectSize
//export C_GetOperationState
//export C_GetSessionInfo
//export C_GetSlotInfo
//export C_GetSlotList
//export C_GetTokenInfo
//export C_Initialize
//export C_InitPIN
//export C_InitToken
//export C_Login
//export C_LoginUser
//export C_Logout
//export C_MessageDecryptFinal
//export C_MessageDecryptInit
//export C_MessageEncryptFinal
//export C_MessageEncryptInit
//export C_MessageSignFinal
//export C_MessageSignInit
//export C_MessageVerifyFinal
//export C_MessageVerifyInit
//export C_OpenSession
//export C_SeedRandom
//export C_SessionCancel
//export C_SetAttributeValue
//export C_SetOperationState
//export C_SetPIN
//export C_Sign
//export C_SignEncryptUpdate
//export C_SignFinal
//export C_SignInit
//export C_SignMessage
//export C_SignMessageBegin
//export C_SignMessageNext
//export C_SignRecover
//export C_SignRecoverInit
//export C_SignUpdate
//export C_UnwrapKey
//export C_Verify
//export C_VerifyFinal
//export C_VerifyInit
//export C_VerifyMessage
//export C_VerifyMessageBegin
//export C_VerifyMessageNext
//export C_VerifyRecover
//export C_VerifyRecoverInit
//export C_VerifyUpdate
//export C_WaitForSlotEvent
//export C_WrapKey
