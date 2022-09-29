//go:generate task generate-client
package main

import "go.formance.com/auth/cmd"

func main() {
	cmd.Execute()
}
