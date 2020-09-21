package main
 
import (
	"os"
	"os/exec"
	"fmt"
	"strings"
	"io/ioutil"
	"./shamir"
	"./aes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/base64"
	"strconv"
)
const(
	SecretShares = 5
	SecretThreshold = 3
)

func readAll(filePth string) ([]byte, error) {
	f, err := os.Open(filePth)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(f)
}

func getToken(file string) (string, error){
	f, err := readAll("token.txt")
	if err != nil {
		return " ", err
	}

	token_pos := strings.Index(string(f), "Root Token:")+len("Root Token:") + 1
	token := string(f)[token_pos: token_pos + 26]
	return token, err
}


func generateShares(secret []byte) ([][]byte, error){
	shares, err := shamir.Split(secret, SecretShares, SecretThreshold)
	if err != nil {
		return nil, err
	}
	//fmt.Println(len(shares))
	for i:=0; i<len(shares);i++{
		fmt.Println(string(shares[i][:]))
	}
	return shares, err
}

func hash(message []byte)(string){
	h := sha256.New()
	h.Write(message)
	r := hex.EncodeToString(h.Sum(nil))	
	//fmt.Printf("%s\n",r)
	return r
}


///////////////////////////////////////////
func userLogin(token string){
	cmd := exec.Command("export", "VAULT_TOKEN='"+token+"'")
	cmd.Run()
	//cmd =exec.Command("vault", "status")
	//buf, err:=cmd.Output()
	//if err != nil {
	//	fmt.Printf("Fail to Login\n")
	//	return
	//}
	//fmt.Printf("%s\n",buf)
	//fmt.Printf("Autenticated\n")
}

func write(serverID int, value [3]string, version string){
	ID := strconv.Itoa(serverID)
	//-cas=0 to prevent rewrite
	cmd := exec.Command("vault", "kv", "put", "-cas=0", "secret/s"+ID+"v"+version,  
		"keyshare="+value[0], 
		"ciphertext="+value[1], 
		"messageDigest="+value[2])

	_, err := cmd.Output()		
	if err != nil {
		fmt.Printf("exist\n")  //write collusion
		cmd := exec.Command("vault", "kv", "delete", "secret/s"+ID+"v"+version) //if three writers?
		cmd.Run()
		return
	}
}


func getVersion(serverID int) (string){ 	//until get no value
	i := 0
	ID := strconv.Itoa(serverID)
	for{
		i = i + 1
		cmd_read := exec.Command("vault", "kv", "get", "secret/s"+ID+"v"+strconv.Itoa(i))
		_, err_read :=cmd_read.Output()		
		
		if err_read != nil {
			break
		}
	}
	//fmt.Printf("current version %d\n", i-1)
	return strconv.Itoa(i-1)
}


func getValue(serverID int, version string) ([3] string){	
	ID := strconv.Itoa(serverID)
	var value [3]string
	cmd_read := exec.Command("vault", "kv", "get", "-field=keyshare","secret/s"+ ID +"v" + version)
	buf_read, _:=cmd_read.Output()	
	value[0] = string(buf_read)

	
	cmd_read = exec.Command("vault", "kv", "get", "-field=ciphertext","secret/s"+ ID +"v" + version)
	buf_read, _ =cmd_read.Output()		
	value[1] = string(buf_read)
	
	cmd_read = exec.Command("vault", "kv", "get", "-field=messageDigest","secret/s"+ ID +"v" + version)
	buf_read, _ =cmd_read.Output()		
	value[2] = string(buf_read)
	
	return value
}


func main() {
	f, err := readAll("token.txt")	//read status from Vault 
	if err != nil {
		return
	}
	token, err := getToken(string(f))	//get token
	if err != nil {
		return
	}
	userLogin(token)	//user login



	shares_read := make([][]byte, SecretShares)
	var ctxt []byte
	var messageDigest string

	for i:=0; i<SecretShares; i++{
		version := getVersion(i)
		var value [3]string
		value = getValue(i, version)

		shares_read[i], _ = base64.StdEncoding.DecodeString(value[0])
		ctxt, _ = base64.StdEncoding.DecodeString(value[1]) 
		messageDigest = value[2]
		
		fmt.Println("Get version ", version, "from server ", i)
	}

	//fmt.Println(shares)
	//fmt.Println(ctxt)
	//fmt.Println(messageDigest)


	recoveredKey, err := shamir.Combine(shares_read)
	if err != nil {
		fmt.Println("combine error")
		return
	}
	fmt.Println("recovered secret key:", string(recoveredKey))	
	decryptedResult, err := aes.DecryptAES(ctxt, recoveredKey)


	fmt.Println("decrypted results:", string(decryptedResult))
	if hash(decryptedResult) == messageDigest {
		fmt.Println("Sha256 matched")
	} 
}



