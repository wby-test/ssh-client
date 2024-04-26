package ssh

import (
	"fmt"
	"os"
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
			cmd:  NewCmd("xxx:22").Password("xxx"),
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

// test scp

func TestCmd_PutData(t *testing.T) {
	tests := []struct {
		name     string
		cmd      *Cmd
		data     string
		file     string
		fileMode os.FileMode
	}{
		{
			name:     "fbcs",
			cmd:      NewCmd("xxx:22").Password("xxx"),
			data:     "./testfile",
			file:     "/root/sshtest",
			fileMode: os.FileMode(os.O_WRONLY | os.O_TRUNC),
		},
		{
			name: "k8s127",
			cmd:  NewCmd("xxx:22").Password("xxx"),
			data: "dfasdfa",
			file: "/root/sshtest",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.cmd
			c.Connect()
			_, err := c.PutData([]byte(tt.data), tt.file, tt.fileMode)
			if err != nil {
				t.Errorf("PutData() error = %v, wantErr %v", err, err)
				return
			}
		})
	}
}

func TestCmd_PutFile(t *testing.T) {
	tests := []struct {
		name     string
		cmd      *Cmd
		data     string
		file     string
		fileMode os.FileMode
	}{
		{
			name:     "fbcs",
			cmd:      NewCmd("xxx:22").Password("xxx"),
			data:     "./testfile",
			file:     "/root/sshtest",
			fileMode: os.FileMode(os.O_WRONLY | os.O_TRUNC),
		},
		{
			name: "k8s127",
			cmd:  NewCmd("xxx:22").Password("xxx"),
			data: "./testfile",
			file: "/root/sshtest",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.cmd
			c.Connect()
			err := c.PutFile(tt.data, tt.file)
			if err != nil {
				t.Errorf("PutData() error = %v, wantErr %v", err, err)
				return
			}
		})
	}
}
