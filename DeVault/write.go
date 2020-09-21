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
	"math/rand"
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

func initialization(newEnv[] string) (){
	cmd_read := exec.Command("vault", "write", myplugin+"/100", "101=testing")
	cmd_read.Env = newEnv
	buf_read, err := cmd_read.CombinedOutput()
	if err!=nil{
		fmt.Println("cmd.Run() failed with ", err)
	}	
	fmt.Println(string(buf_read))
	//
	cmd_read = exec.Command("vault", "write", myplugin+"/6400", "102=testing")
	cmd_read.Env = newEnv	
	buf_read, err = cmd_read.CombinedOutput()
	if err!=nil{
		fmt.Println("cmd.Run() failed with ", err)
	}	
	fmt.Println(string(buf_read))
	//	
	cmd_read = exec.Command("vault", "write", myplugin+"/5200", "104=testing")
	cmd_read.Env = newEnv	
	buf_read, err = cmd_read.CombinedOutput()
	if err!=nil{
		fmt.Println("cmd.Run() failed with ", err)
	}	
	fmt.Println(string(buf_read))
	//	
	cmd_read = exec.Command("vault", "write", myplugin+"/50", "53=testing")
	cmd_read.Env = newEnv	
	buf_read, err = cmd_read.CombinedOutput()
	if err!=nil{
		fmt.Println("cmd.Run() failed with ", err)
	}	
	fmt.Println(string(buf_read))
}


var myplugin string = "my-plugins"
func main() {		
	servers := [SecretShares] int {6400, 7200, 7800,}
	
		
	var promiseCount int = 0	// store the number of promise response
	var existingMaxPID int = 0	// store the max PID with value
	var existingValue map[int]string// store the stored value of previous PID
	existingValue = make(map[int]string)

	//-----------get the lastest version-------------
	var versionToPropose int = 0	
	for _, serverID := range servers{
		newEnv := prepareEnv(serverID) //prepare environment on the fly
		
		cmd_enable := exec.Command("vault", "secrets", "enable", myplugin)
		cmd_enable.Env = newEnv
		cmd_enable.CombinedOutput()
		//initialize sth for testing
		//initialization(newEnv)

		cmd_read := exec.Command("vault", "list", myplugin)
		cmd_read.Env = newEnv	
		buf_read, err := cmd_read.CombinedOutput()
		if err!=nil{
			fmt.Println("cmd.Run() failed with ", err)
		}			
		a := strings.Split(string(buf_read), "\n")		
		fmt.Println("Latest version of Server", serverID,": ", a[2])		
		receivedVersion, _ := strconv.Atoi(a[2])
		if (receivedVersion > versionToPropose) {versionToPropose = receivedVersion}	
	}
	versionToPropose++
	proposalID := rand.Intn(1000)
	fmt.Println("Going to write version: ", versionToPropose, "with proposal ID:", proposalID)	
	

	//write
	for _, serverID := range servers{
		newEnv := prepareEnv(serverID) //prepare environment on the fly
		
		//----------------------------------------------------------------------
		//-------------------------make proposal--------------------------------
		//----------------------------------------------------------------------
		cmd_proposal := exec.Command("vault", "write", myplugin+"/"+strconv.Itoa(versionToPropose), 
			strconv.Itoa(proposalID)+"=0")
		cmd_proposal.Env = newEnv	
		buf_proposal, _ := cmd_proposal.CombinedOutput()
		
		s_buf_proposal := strings.Split(string(buf_proposal), "\"")
		length := len(s_buf_proposal)
		if(length == 1){
			s_buf_proposal2 := strings.Split(string(buf_proposal), ":")	
			s_buf_proposal3 := strings.Split(s_buf_proposal2[len(s_buf_proposal2)-2]," ")

			if(s_buf_proposal3[len(s_buf_proposal3)-1] == "higherProposal"){		
				fmt.Println( "Response from server", serverID, ": exist higher proposal:", s_buf_proposal2[len(s_buf_proposal2)-1] )
			}else if (s_buf_proposal3[len(s_buf_proposal3)-1] == "promise"){
				fmt.Println( "Response from server", serverID, " :promise", s_buf_proposal2[len(s_buf_proposal2)-1])
				promiseCount++
			}else{//should not be here		
				fmt.Println("Response from server", serverID, string(buf_proposal))
			}

		}else{	//existing value
			fmt.Println("existing PID:"+ s_buf_proposal[1] + " value:" + s_buf_proposal[3])
			receivedPID, _ := strconv.Atoi(s_buf_proposal[1])
			if (existingMaxPID < receivedPID){existingMaxPID = receivedPID}
			existingValue[receivedPID] = s_buf_proposal[3]
		}	
		
	}	
	receivedResp := promiseCount + len(existingValue)
	if (receivedResp < SecretThreshold){
		fmt.Println("get ", receivedResp, " <", SecretThreshold)		
		fmt.Println("Should retry")
	}else{	
		
		fmt.Println("get ", receivedResp, " >=", SecretThreshold)
		
		//----------------------------------------------------------------------
		//-------------------------------accept---------------------------------
		//----------------------------------------------------------------------

		if(len(existingValue) !=0){
			//write with exiting value
			messageDigest := existingValue[existingMaxPID]
			for _, serverID := range servers{	
				newEnv := prepareEnv(serverID) //prepare environment on the fly
				cmd_accept := exec.Command("vault", "write",
					myplugin+"/"+strconv.Itoa(versionToPropose), 
					strconv.Itoa(proposalID) +"="+messageDigest+",0,0")

				cmd_accept.Env = newEnv	
				_, err := cmd_accept.CombinedOutput()
				if err==nil{
					fmt.Println("Wrote to Server", serverID, 
						"\n digest:", messageDigest,
						"\n shard: 0",
						"\n ctxt:  0" )
				}
			}


		}else{
			//write with new value
			Key := []byte("HGFEDCBA87654321")	//generate secret key to be shared
	 		message := []byte("helloworld???") 	//message to be transferred
			messageDigest := hash(message) 		//before aes.enc, message will be padded afterwards
			//fmt.Println("Secret key: ", string(Key))
			fmt.Println("Message to put: ", string(message))
			ctxt, _ := aes.EncryptAES(message, Key)
			shares, _ := generateShares(Key)  

			for i, serverID := range servers{	
				newEnv := prepareEnv(serverID) //prepare environment on the fly
				encodedShare := base64.StdEncoding.EncodeToString(shares[i][:])
				encodedCtxt  := base64.StdEncoding.EncodeToString(ctxt)

				cmd_accept := exec.Command("vault", "write", 					myplugin+"/"+strconv.Itoa(versionToPropose), 
				strconv.Itoa(proposalID) +"="+messageDigest+","+encodedShare+","+encodedCtxt)

				cmd_accept.Env = newEnv	
				_, err := cmd_accept.CombinedOutput()
				if err==nil{
					fmt.Println("Wrote to Server", serverID, 
						"\n digest:", messageDigest,
						"\n shard: ", encodedShare,
						"\n ctxt:  ", encodedCtxt )
				}
			}
		}
	}

	return
}



