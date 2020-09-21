package main
 
import (
	"os"
	"os/exec"
	"io"
	"bufio"
	"fmt"
)

func main() {
	cmd := exec.Command("vault", "server", "-dev")
	f, err := os.Create("token.txt")
	defer f.Close()
	//StdoutPipe方法返回一个在命令Start后与命令标准输出关联的管道。Wait方法获知命令结束后会关闭这个管道，一般不需要显式的关闭该管道。
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println("cmd.StdoutPipe: ", err)
		return
	}
	//cmd.Stderr = os.Stderr
	err = cmd.Start()
	if err != nil {
		return
	}
	//创建一个流来读取管道内内容，这里逻辑是通过一行一行的读取的
	reader := bufio.NewReader(stdout)
	//实时循环读取输出流中的一行内容
	for {
		line, err2 := reader.ReadString('\n')
		if err2 != nil || io.EOF == err2 {
			break
		}
		_, err = f.WriteString(line) //写入文件(字节数组)
		f.Sync()
	}
	err = cmd.Wait()
	return
}

