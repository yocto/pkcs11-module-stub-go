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
func C_CopyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/, phNewObject C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_CreateObject
func C_CreateObject(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/, phObject C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Decrypt
func C_Decrypt(hSession C.CK_SESSION_HANDLE, pEncryptedData C.CK_BYTE_PTR, ulEncryptedDataLen C.CK_ULONG /*usEncryptedDataLen C.CK_USHORT (v1.0)*/, pData C.CK_BYTE_PTR, pulDataLen C.CK_ULONG_PTR /*pusDataLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DecryptDigestUpdate
func C_DecryptDigestUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DecryptFinal
func C_DecryptFinal(hSession C.CK_SESSION_HANDLE, pLastPart C.CK_BYTE_PTR, pulLastPartLen C.CK_ULONG_PTR /*usLastPartLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
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
func C_DecryptUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG /*usEncryptedPartLen C.CK_USHORT (v1.0)*/, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR /*pusPartLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DecryptVerifyUpdate
func C_DecryptVerifyUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR, ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR, pulPartLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DeriveKey
func C_DeriveKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hBaseKey C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulAttributeCount C.CK_ULONG /*usAttributeCount C.CK_USHORT (v1.0)*/, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DestroyObject
func C_DestroyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Digest
func C_Digest(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pDigest C.CK_BYTE_PTR, pulDigestLen C.CK_ULONG_PTR /*pusDigestLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestEncryptUpdate
func C_DigestEncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestFinal
func C_DigestFinal(hSession C.CK_SESSION_HANDLE, pDigest C.CK_BYTE_PTR, pulDigestLen C.CK_ULONG_PTR /*pusDigestLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestInit
func C_DigestInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestKey
func C_DigestKey(hSession C.CK_SESSION_HANDLE, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v2.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestUpdate
func C_DigestUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG /*usPartLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Encrypt
func C_Encrypt(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pEncryptedData C.CK_BYTE_PTR, pulEncryptedDataLen C.CK_ULONG_PTR /*pusEncryptedDataLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_EncryptFinal
func C_EncryptFinal(hSession C.CK_SESSION_HANDLE, pLastEncryptedPart C.CK_BYTE_PTR, pulLastEncryptedPartLen C.CK_ULONG_PTR /*pusEncryptedPartLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
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
func C_EncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG /*usPartLen C.CK_USHORT (v1.0)*/, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR /*pusEncryptedPartLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Finalize
func C_Finalize(pReserved C.CK_VOID_PTR) C.CK_RV { // Since v2.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_FindObjects
func C_FindObjects(hSession C.CK_SESSION_HANDLE, phObject C.CK_OBJECT_HANDLE_PTR, ulMaxObjectCount C.CK_ULONG /*usMaxObjectCount C.CK_USHORT (v1.0)*/, pulObjectCount C.CK_ULONG_PTR /*pusObjectCount C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_FindObjectsFinal
func C_FindObjectsFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV { // Since v2.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_FindObjectsInit
func C_FindObjectsInit(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GenerateKey
func C_GenerateKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GenerateKeyPair
func C_GenerateKeyPair(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pPublicKeyTemplate C.CK_ATTRIBUTE_PTR, ulPublicKeyAttributeCount C.CK_ULONG /*usPublicKeyAttributeCount C.CK_USHORT (v1.0)*/, pPrivateKeyTemplate C.CK_ATTRIBUTE_PTR, ulPrivateKeyAttributeCount C.CK_ULONG /*usPrivateKeyAttributeCount C.CK_USHORT (v1.0)*/, phPrivateKey C.CK_OBJECT_HANDLE_PTR, phPublicKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GenerateRandom
func C_GenerateRandom(hSession C.CK_SESSION_HANDLE, pRandomData C.CK_BYTE_PTR, ulRandomLen C.CK_ULONG /*usRandomLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetAttributeValue
func C_GetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
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
func C_GetInfo(pInfo C.CK_INFO_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetInterface
//export C_GetInterfaceList

//export C_GetMechanismInfo
func C_GetMechanismInfo(slotID C.CK_SLOT_ID, _type C.CK_MECHANISM_TYPE, pInfo C.CK_MECHANISM_INFO_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetMechanismList
func C_GetMechanismList(slotID C.CK_SLOT_ID, pMechanismList C.CK_MECHANISM_TYPE_PTR, pulCount C.CK_ULONG_PTR /*pusCount C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetObjectSize
func C_GetObjectSize(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pulSize C.CK_ULONG_PTR /*pusSize C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetOperationState
func C_GetOperationState(hSession C.CK_SESSION_HANDLE, pOperationState C.CK_BYTE_PTR, pulOperationStateLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

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
func C_GetSlotList(tokenPresent C.CK_BBOOL, pSlotList C.CK_SLOT_ID_PTR, pulCount C.CK_ULONG_PTR /*pusCount C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetTokenInfo
func C_GetTokenInfo(slotID C.CK_SLOT_ID, pInfo C.CK_TOKEN_INFO_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Initialize
func C_Initialize(pInitArgs C.CK_VOID_PTR /*pReserved C.CK_VOID_PTR (v1.0,v2.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_InitPIN
func C_InitPIN(hSession C.CK_SESSION_HANDLE, pPin C.CK_CHAR_PTR, ulPinLen C.CK_ULONG /*usPinLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_InitToken
func C_InitToken(slotID C.CK_SLOT_ID, pPin C.CK_CHAR_PTR, ulPinLen C.CK_ULONG /*usPinLen C.CK_USHORT (v1.0)*/, pLabel C.CK_CHAR_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Login
func C_Login(hSession C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_CHAR_PTR, ulPinLen C.CK_ULONG /*usPinLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
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

//export C_OpenSession
func C_OpenSession(slotID C.CK_SLOT_ID, flags C.CK_FLAGS, pApplication C.CK_VOID_PTR, Notify C.CK_NOTIFY /*CK_RV (*Notify)(CK_SESSION_HANDLE hSession, C.CK_NOTIFICATION event, C.CK_VOID_PTR pApplication) (v1.0)*/, phSession C.CK_SESSION_HANDLE_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SeedRandom
func C_SeedRandom(hSession C.CK_SESSION_HANDLE, pSeed C.CK_BYTE_PTR, ulSeedLen C.CK_ULONG /*usSeedLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SessionCancel

//export C_SetAttributeValue
func C_SetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG /*usCount C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SetOperationState
func C_SetOperationState(hSession C.CK_SESSION_HANDLE, pOperationState C.CK_BYTE_PTR, ulOperationStateLen C.CK_ULONG, hEncryptionKey C.CK_OBJECT_HANDLE, hAuthenticationKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v2.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SetPIN
func C_SetPIN(hSession C.CK_SESSION_HANDLE, pOldPin C.CK_CHAR_PTR, ulOldLen C.CK_ULONG /*usOldLen C.CK_USHORT (v1.0)*/, pNewPin C.CK_CHAR_PTR, ulNewLen C.CK_ULONG /*usNewLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Sign
func C_Sign(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR /*pusSignatureLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SignEncryptUpdate
func C_SignEncryptUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG, pEncryptedPart C.CK_BYTE_PTR, pulEncryptedPartLen C.CK_ULONG_PTR) C.CK_RV { // Since v2.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SignFinal
func C_SignFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR /*pusSignatureLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
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
func C_SignRecover(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR /*pusSignatureLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SignRecoverInit
func C_SignRecoverInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SignUpdate
func C_SignUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG /*usPartLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_UnwrapKey
func C_UnwrapKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hUnwrappingKey C.CK_OBJECT_HANDLE, pWrappedKey C.CK_BYTE_PTR, ulWrappedKeyLen C.CK_ULONG /*usWrappedKeyLen C.CK_USHORT (v1.0)*/, pTemplate C.CK_ATTRIBUTE_PTR, ulAttributeCount C.CK_ULONG /*usAttributeCount C.CK_USHORT (v1.0)*/, phKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Verify
func C_Verify(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG /*usDataLen C.CK_USHORT (v1.0)*/, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG /*usSignatureLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyFinal
func C_VerifyFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG /*usSignatureLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
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
func C_VerifyRecover(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG /*usSignatureLen C.CK_USHORT (v1.0)*/, pData C.CK_BYTE_PTR, pulDataLen C.CK_ULONG_PTR /*pusDataLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyRecoverInit
func C_VerifyRecoverInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyUpdate
func C_VerifyUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG /*usPartLen C.CK_USHORT (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_WaitForSlotEvent
func C_WaitForSlotEvent(flags C.CK_FLAGS, pSlot C.CK_SLOT_ID_PTR, pReserved C.CK_VOID_PTR) C.CK_RV { // Since v2.01
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_WrapKey
func C_WrapKey(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hWrappingKey C.CK_OBJECT_HANDLE, hKey C.CK_OBJECT_HANDLE, pWrappedKey C.CK_BYTE_PTR, pulWrappedKeyLen C.CK_ULONG_PTR /*pusWrappedKeyLen C.CK_USHORT_PTR (v1.0)*/) C.CK_RV { // Since v1.0
	// TODO
	return C.CKR_FUNCTION_NOT_SUPPORTED
}
