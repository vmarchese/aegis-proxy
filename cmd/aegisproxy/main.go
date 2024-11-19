package main

import (
	"fmt"
	"os"
)

var exitCode int

func main() {

	defer exit()

	if err := rootCmd.Execute(); err != nil {
		fmt.Println("Aegis Proxy execution terminated with error: ", err)
		exitCode = 1
		return
	}
}

func exit() {
	os.Exit(exitCode)
}
