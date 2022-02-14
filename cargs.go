//+build cargs

package cargs

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/salsa20"
	"os"
	"strings"
)

// init cargs
// only flag occur,cargs crypto rest args,otherwise decrypt os.args[1]
func Init(key []byte, flag string) {
	// generate [32]byte key
	keyA := md5.Sum(key)
	keyB := md5.Sum(append(keyA[:], []byte(flag)...))
	key32 := [32]byte{}
	copy(key32[0:], keyA[:])
	copy(key32[16:], keyB[:])
	nonce := key32[8:16]
	if len(flag) == 0 {
		fmt.Println("error: empty flag!")
		os.Exit(1)
	}
	var newArgs []string
	newArgs = append(newArgs, os.Args[0])
	if len(os.Args) > 2 && os.Args[1] == flag {
		// encode args
		input := []byte(strings.Join(os.Args[2:], " "))
		output := make([]byte, len(input))
		salsa20.XORKeyStream(output, input, nonce, &key32)
		fmt.Printf("cargs output: %s\n", base64.StdEncoding.EncodeToString(output))
		os.Exit(0)
	} else if len(os.Args) == 2 {
		input, err := base64.StdEncoding.DecodeString(os.Args[1])
		if err != nil {
			//fmt.Println(err)
			os.Exit(1)
		}
		output := make([]byte, len(input))
		salsa20.XORKeyStream(output, input, nonce, &key32)
		os.Args = append(os.Args[:1], strings.Split(string(output), " ")...)
	} else {
		os.Exit(0)
	}
}
