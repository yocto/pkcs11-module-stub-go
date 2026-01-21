package main

import "fmt"

var functionList = C.CK_FUNCTION_LIST{}

func main() {}

//export C_GetFunctionList
func C_GetFunctionList(ppFunctionList C.CK_FUNCTION_LIST_PTR_PTR) C.CK_RV {
	fmt.Printf("[CALLED]: C_GetFunctionList(ppFunctionList=%s)\n", ppFunctionList)

	if ppFunctionList == nil {
		fmt.Println(" - ppFunctionList IS NULL")
		return C.CKR_ARGUMENTS_BAD
	}

	*ppFunctionList = &functionList

	return C.CK_OK
}
