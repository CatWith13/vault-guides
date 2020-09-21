package aes

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
)

const( 
	BlockSize = 16
)

func padding(src []byte, blockSize int) []byte {
    padNum := blockSize - len(src) % blockSize
    pad := bytes.Repeat([]byte{byte(padNum)}, padNum)
    return append(src, pad...)
}

func unpadding(src []byte) []byte {
    n := len(src)
    unPadNum := int(src[n-1])
    return src[:n-unPadNum]
}

//encrypt
func EncryptAES(src []byte, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    src = padding(src, block.BlockSize())
    blockMode := cipher.NewCBCEncrypter(block, key)
    blockMode.CryptBlocks(src, src)
    return src, nil
}

//decrypt
func DecryptAES(src []byte, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    blockMode := cipher.NewCBCDecrypter(block, key)
    blockMode.CryptBlocks(src, src)
    src = unpadding(src)
    return src, nil
}

