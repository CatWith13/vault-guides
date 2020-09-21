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
	//fmt.Println(shares)
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
func userLogin(token string){	//wtf
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
	cmd := exec.Command("vault", "kv", "put", "-cas=0", "secret/s"+ID+"v"+version, "keyshare="+value[0], "messageDigest="+value[1], "ciphertext="+value[2])
	
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
	//fmt.Printf("version to be write %d\n", i)
	return strconv.Itoa(i)
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

	

	
	Key := []byte("HGFEDCBA87654321")	//generate secret key to be shared
 	message := []byte("helloworld") 	//message to be transferred
	messageDigest := hash(message) 		//before aes.enc, message will be padded afterwards
	
	fmt.Println("Secret key: ", string(Key))
	fmt.Println("Message to put: ", string(message))

	ctxt, err := aes.EncryptAES(message, Key)
    	if err != nil {
        	return
    	}
	//fmt.Println(string(ctxt[:]))

	shares, err := generateShares(Key)  //3-out-of-5 secret sharing over secret key
	fmt.Println("Secret key: ", string(Key))
	if err != nil {
		return
	}

	
	for i:=0; i<len(shares);i++{ 	//put shares to servers
		value := [3] string {
			base64.StdEncoding.EncodeToString(shares[i][:]), 
			messageDigest, 
			base64.StdEncoding.EncodeToString(ctxt),
		}
		version := getVersion(i)
		write(i, value, version)
		fmt.Println("Put version ", version, "in server ", i)
	}
	
}

