package util

import "fmt"

func Debug(data interface{}) {
	fmt.Printf("%+v\n", data)
}
