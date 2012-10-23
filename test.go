package main

import (
       "code.google.com/p/go.crypto/nacl/box"
       "crypto/rand"
       "fmt"
)

func main() {
     pub, priv, _ := box.GenerateKey(rand.Reader)
     fmt.Println(pub)
     fmt.Println(priv)
}
