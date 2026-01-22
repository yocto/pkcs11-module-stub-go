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
func C_DecryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DecryptMessage
//export C_DecryptMessageBegin
//export C_DecryptMessageNext

//export C_DecryptUpdate
func C_DecryptUpdate(hSession CK_SESSION_HANDLE, pEncryptedPart CK_BYTE_PTR, usEncryptedPartLen CK_USHORT, pPart CK_BYTE_PTR, pusPartLen CK_USHORT_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DecryptVerifyUpdate

//export C_DeriveKey
func C_DeriveKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hBaseKey C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, usAttributeCount C.CK_USHORT, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DestroyObject
func C_DestroyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Digest
func C_Digest(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, usDataLen C.CK_USHORT, pDigest C.CK_BYTE_PTR, pusDigestLen C.CK_USHORT_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestEncryptUpdate

//export C_DigestFinal
func C_DigestFinal(hSession C.CK_SESSION_HANDLE, pDigest C.CK_BYTE_PTR, pusDigestLen C.CK_USHORT_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestInit
func C_DigestInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestKey

//export C_DigestUpdate
func C_DigestUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, usPartLen C.CK_USHORT) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Encrypt
func C_Encrypt(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, usDataLen C.CK_USHORT, pEncryptedData C.CK_BYTE_PTR, pusEncryptedDataLen C.CK_USHORT_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_EncryptFinal
func C_EncryptFinal(hSession C.CK_SESSION_HANDLE, pLastEncryptedPart C.CK_BYTE_PTR, pusEncryptedPartLen C.CK_USHORT_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_EncryptInit
func C_EncryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_EncryptMessage
//export C_EncryptMessageBegin
//export C_EncryptMessageNext

//export C_EncryptUpdate
func C_EncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, usPartLen C.CK_USHORT, pEncryptedPart C.CK_BYTE_PTR, pusEncryptedPartLen C.CK_USHORT_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Finalize

//export C_FindObjects
func C_FindObjects(hSession C.CK_SESSION_HANDLE, phObject C.CK_OBJECT_HANDLE_PTR, usMaxObjectCount C.CK_USHORT, pusObjectCount C.CK_USHORT_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_FindObjectsFinal

//export C_FindObjectsInit
func C_FindObjectsInit(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, usCount C.CK_USHORT) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GenerateKey
func C_GenerateKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pTemplate C.CK_ATTRIBUTE_PTR, usCount C.CK_USHORT, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GenerateKeyPair
func C_GenerateKeyPair(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pPublicKeyTemplate C.CK_ATTRIBUTE_PTR, usPublicKeyAttributeCount C.CK_USHORT, pPrivateKeyTemplate C.CK_ATTRIBUTE_PTR, usPrivateKeyAttributeCount C.CK_USHORT, phPrivateKey C.CK_OBJECT_HANDLE_PTR, phPublicKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GenerateRandom
func C_GenerateRandom(hSession C.CK_SESSION_HANDLE, pRandomData C.CK_BYTE_PTR, usRandomLen C.CK_USHORT) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetAttributeValue
func C_GetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, usCount C.CK_USHORT) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetFunctionList
func C_GetFunctionList(ppFunctionList C.CK_FUNCTION_LIST_PTR_PTR) C.CK_RV { // Since v2.0
	fmt.Printf("[CALLED]: C_GetFunctionList(ppFunctionList=%+v)\n", ppFunctionList)

	if ppFunctionList == nil {
		fmt.Println(" - ppFunctionList IS NULL")
		return C.CKR_ARGUMENTS_BAD
	}

	*ppFunctionList = &functionList

	return C.CKR_OK
}

//export C_GetFunctionStatus
func C_GetFunctionStatus(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetInfo
func C_GetInfo(pInfo CK_INFO_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetInterface
//export C_GetInterfaceList

//export C_GetMechanismInfo
func C_GetMechanismInfo(slotID CK_SLOT_ID, _type CK_MECHANISM_TYPE, pInfo CK_MECHANISM_INFO_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetMechanismList
func C_GetMechanismList(slotID CK_SLOT_ID, pMechanismList CK_MECHANISM_TYPE_PTR, pusCount CK_USHORT_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetObjectSize
func C_GetObjectSize(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pusSize C.CK_USHORT_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetOperationState

//export C_GetSessionInfo
func C_GetSessionInfo(hSession C.CK_SESSION_HANDLE, pInfo C.CK_SESSION_INFO_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetSlotInfo
func C_GetSlotInfo(slotID C.CK_SLOT_ID, pInfo C.CK_SLOT_INFO_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetSlotList
func C_GetSlotList(tokenPresent C.CK_BBOOL, pSlotList C.CK_SLOT_ID_PTR, pusCount C.CK_USHORT_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetTokenInfo
func C_GetTokenInfo(slotID C.CK_SLOT_ID, pInfo C.CK_TOKEN_INFO_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Initialize
func C_Initialize(pReserved C.CK_VOID_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_InitPIN
func C_InitPIN(hSession C.CK_SESSION_HANDLE, pPin C.CK_CHAR_PTR, usPinLen C.CK_USHORT) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_InitToken
func C_InitToken(slotID C.CK_SLOT_ID, pPin C.CK_CHAR_PTR, usPinLen C.CK_USHORT, pLabel C.CK_CHAR_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Login
func C_Login(hSession C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_CHAR_PTR, usPinLen C.CK_USHORT) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_LoginUser

//export C_Logout
func C_Logout(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_MessageDecryptFinal
//export C_MessageDecryptInit
//export C_MessageEncryptFinal
//export C_MessageEncryptInit
//export C_MessageSignFinal
//export C_MessageSignInit
//export C_MessageVerifyFinal
//export C_MessageVerifyInit

// _ = CK_RV (*Notify)(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event, CK_VOID_PTR pApplication)
//
//export C_OpenSession
func C_OpenSession(slotID C.CK_SLOT_ID, flags C.CK_FLAGS, pApplication C.CK_VOID_PTR, _ interface{}, phSession C.CK_SESSION_HANDLE_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SeedRandom
func C_SeedRandom(hSession C.CK_SESSION_HANDLE, pSeed C.CK_BYTE_PTR, usSeedLen C.CK_USHORT) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SessionCancel

//export C_SetAttributeValue
func C_SetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, usCount C.CK_USHORT) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SetOperationState

//export C_SetPIN
func C_SetPIN(hSession C.CK_SESSION_HANDLE, pOldPin C.CK_CHAR_PTR, usOldLen C.CK_USHORT, pNewPin C.CK_CHAR_PTR, usNewLen C.CK_USHORT) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Sign
func C_Sign(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, usDataLen C.CK_USHORT, pSignature C.CK_BYTE_PTR, pusSignatureLen C.CK_USHORT_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SignEncryptUpdate

//export C_SignFinal
func C_SignFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, pusSignatureLen C.CK_USHORT_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SignInit
func C_SignInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SignMessage
//export C_SignMessageBegin
//export C_SignMessageNext

//export C_SignRecover
func C_SignRecover(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, usDataLen C.CK_USHORT, pSignature C.CK_BYTE_PTR, pusSignatureLen C.CK_USHORT_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SignRecoverInit
func C_SignRecoverInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SignUpdate
func C_SignUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, usPartLen C.CK_USHORT) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_UnwrapKey
func C_UnwrapKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hUnwrappingKey C.CK_OBJECT_HANDLE, pWrappedKey C.CK_BYTE_PTR, usWrappedKeyLen C.CK_USHORT, pTemplate C.CK_ATTRIBUTE_PTR, usAttributeCount C.CK_USHORT, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Verify
func C_Verify(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, usDataLen C.CK_USHORT, pSignature C.CK_BYTE_PTR, usSignatureLen C.CK_USHORT) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyFinal
func C_VerifyFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, usSignatureLen C.CK_USHORT) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyInit
func C_VerifyInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyMessage
//export C_VerifyMessageBegin
//export C_VerifyMessageNext

//export C_VerifyRecover
func C_VerifyRecover(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, usSignatureLen C.CK_USHORT, pData C.CK_BYTE_PTR, pusDataLen C.CK_USHORT_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyRecoverInit
func C_VerifyRecoverInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyUpdate
func C_VerifyUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, usPartLen C.CK_USHORT) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_WaitForSlotEvent
func C_WaitForSlotEvent(flags C.CK_FLAGS, pSlot C.CK_SLOT_ID_PTR, pReserved C.CK_VOID_PTR) C.CK_RV { // Since v2.1
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_WrapKey
func C_WrapKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hWrappingKey C.CK_OBJECT_HANDLE, hKey C.CK_OBJECT_HANDLE, pWrappedKey C.CK_BYTE_PTR, pusWrappedKeyLen C.CK_USHORT_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}
