package main
import "fmt"
import "os/exec"
func main(){
	cmd := exec.Command("cat", "/etc/passwd")
	output, err := cmd.Output()
		if err != nil {
		fmt.Println("Error running command:", err)
		return
	}
	fmt.Println(string(output))
}