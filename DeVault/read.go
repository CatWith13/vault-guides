package main
 
import (
	"os"
	"os/exec"
	"fmt"
	"strings"
	"./shamir"
	"./aes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/base64"
	"strconv"
	
	"net/url"
	//"math/rand"
)
const(
	SecretShares = 3
	SecretThreshold = 2
)


func generateShares(secret []byte) ([][]byte, error){
	shares, err := shamir.Split(secret, SecretShares, SecretThreshold)
	if err != nil {
		return nil, err
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


func prepareEnv(serverID int)([] string){	
	rawUrl := "http://127.0.0.1:" + strconv.Itoa(serverID)
	newUrl, _ := url.Parse(rawUrl)
	addEnv := "VAULT_ADDR=" + newUrl.String()
	newEnv := append(os.Environ(), addEnv)
	return newEnv
}

var myplugin string = "my-plugins"
func main() {		
	servers := [SecretShares] int {6400, 7200, 7800,}

	var versionCount map[int]int// store the stored value of previous PID
	versionCount = make(map[int]int)
	//-----------get the lastest version-------------
	var versionToRead int = 0	
	for _, serverID := range servers{
		newEnv := prepareEnv(serverID) //prepare environment on the fly
		
		cmd_enable := exec.Command("vault", "secrets", "enable", myplugin)
		cmd_enable.Env = newEnv
		cmd_enable.CombinedOutput()

		cmd_read := exec.Command("vault", "list", myplugin)
		cmd_read.Env = newEnv	
		buf_read, err := cmd_read.CombinedOutput()
		if err!=nil{
			fmt.Println("cmd.Run() failed with ", err)
		}			
		a := strings.Split(string(buf_read), "\n")		
		fmt.Println("Latest version of Server", serverID,": ", a[2])		
		receivedVersion, _ := strconv.Atoi(a[2])
		if _, ok := versionCount[receivedVersion]; ok{
			versionCount[receivedVersion]++
		}else{
			versionCount[receivedVersion] = 1
		}
	}

	for version, count := range(versionCount){
		fmt.Println("version:", version, "count:", count)
		if (count >= SecretThreshold) {versionToRead = version}
	}
	if(versionToRead == 0) {return}
	
	fmt.Println("Going to read version: ", versionToRead)	
	shares_read := make([][]byte, SecretShares)
	var ctxt []byte
	var messageDigest string	

	//write
	for i, serverID := range servers{
		newEnv := prepareEnv(serverID) //prepare environment on the fly

		//-------------------------read hash-------------------------------
		cmd_read := exec.Command("vault", "read", myplugin+"/"+strconv.Itoa(versionToRead))
		cmd_read.Env = newEnv	
		buf_read, _ := cmd_read.CombinedOutput()
		
		s_buf_read := strings.Split(string(buf_read), "\n")
		s_buf_read2:= strings.Split(string(s_buf_read[2]), " ")
		messageDigest = s_buf_read2[len(s_buf_read2)-1]
		
		//-------------------------read ctxt-------------------------------
		cmd_read = exec.Command("vault", "read", myplugin+"/"+strconv.Itoa(versionToRead)+"-ctxt")
		cmd_read.Env = newEnv	
		buf_read, _ = cmd_read.CombinedOutput()
		
		s_buf_read = strings.Split(string(buf_read), "\n")
		s_buf_read2= strings.Split(string(s_buf_read[2]), " ")
		if(s_buf_read2[len(s_buf_read2)-1] == "0") {continue}
		ctxt, _ = base64.StdEncoding.DecodeString( s_buf_read2[len(s_buf_read2)-1] )

		//------------------------read share-------------------------------
		cmd_read = exec.Command("vault", "read", myplugin+"/"+strconv.Itoa(versionToRead)+"-share")
		cmd_read.Env = newEnv	
		buf_read, _ = cmd_read.CombinedOutput()
		
		s_buf_read = strings.Split(string(buf_read), "\n")
		s_buf_read2= strings.Split(string(s_buf_read[2]), " ")
		if(s_buf_read2[len(s_buf_read2)-1] == "0") {continue}
		shares_read[i], _ = base64.StdEncoding.DecodeString( s_buf_read2[len(s_buf_read2)-1] )
	}
	recoveredKey, err := shamir.Combine(shares_read)
	if err != nil {
		fmt.Println("combine error")
		return
	}
	fmt.Println("recovered secret key:", string(recoveredKey))	
	decryptedResult, err := aes.DecryptAES(ctxt, recoveredKey)


	fmt.Println("decrypted results:", string(decryptedResult))
	if hash(decryptedResult) == messageDigest {
		fmt.Println("SHA256 matched")
	} 
	
	return
}



