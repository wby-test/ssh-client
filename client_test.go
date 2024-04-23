package ssh

import (
	"fmt"
	"testing"
)

func Test(t *testing.T) {

}

func TestCmd_RunCmd(t *testing.T) {
	tests := []struct {
		name string
		cmd  *Cmd
	}{
		{
			name: "fbcs",
			cmd:  NewCmd("xxxx:22").Password("xxx"),
		},
		{
			name: "k8s127",
			cmd:  NewCmd("xxx:22").Password("xxx"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := tt.cmd.Connect()
			if err != nil {
				t.Fatal(err)
			}
			defer cmd.Close()
			r := cmd.RunCmd("ls -al")
			fmt.Println(r.Detail())
		})
	}
}
