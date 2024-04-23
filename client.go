package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/golang/glog"
)

var SSHCiphers = []string{
	"aes128-ctr",
	"aes192-ctr",
	"aes256-ctr",
	"aes128-gcm@openssh.com",
	"arcfour256",
	"arcfour128",
	"aes128-cbc",
	"3des-cbc",
	"aes192-cbc",
	"aes256-cbc",
}

type Cmd struct {
	addr           string
	username       string
	password       string
	keyFile        string
	client         *ssh.Client
	connectTimeout time.Duration
	ioTimeout      time.Duration
}

func NewCmd(addr string) *Cmd {
	return &Cmd{addr: addr, username: "root", connectTimeout: 10 * time.Second, ioTimeout: 10 * time.Second}
}

func (c *Cmd) User(username string) *Cmd {
	c.username = username
	return c
}

func (c *Cmd) Password(password string) *Cmd {
	c.password = password
	return c
}

func (c *Cmd) KeyFile(keyFile string) *Cmd {
	c.keyFile = keyFile
	return c
}

func (c *Cmd) ConnectTimeout(connectTimeout time.Duration) *Cmd {
	if connectTimeout > 0 {
		c.connectTimeout = connectTimeout
	}
	return c
}

func (c *Cmd) IoTimeout(ioTimeout time.Duration) *Cmd {
	if ioTimeout > 0 {
		c.ioTimeout = ioTimeout
	}
	return c
}

func (c *Cmd) Connect() (*Cmd, error) {
	glog.Info("connect to %s@%s. conn-timeout=%v. io-timeout=%v.", c.username, c.addr, c.connectTimeout, c.ioTimeout)
	auth, err := c.genAuthMethod()
	if err != nil {
		return c, err
	}
	clientConfig := &ssh.ClientConfig{
		Auth:            auth,
		User:            c.username,
		Timeout:         c.connectTimeout,
		Config:          ssh.Config{Ciphers: SSHCiphers},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil },
	}
	conn, err := net.DialTimeout("tcp", c.addr, c.connectTimeout)
	if err != nil {
		return nil, fmt.Errorf("net.dial failed. %w", err)
	}
	timeoutConn := &Conn{conn, c.ioTimeout, c.ioTimeout}
	sshConn, chans, reqs, err := ssh.NewClientConn(timeoutConn, c.addr, clientConfig)
	if err != nil {
		return nil, fmt.Errorf("ssh.conn failed. %w", err)
	}

	c.client = ssh.NewClient(sshConn, chans, reqs)
	return c, nil
}

func (c *Cmd) Close() {
	if c.client != nil {
		c.client.Close()
		c.client = nil
	}
}

func (c *Cmd) genAuthMethod() ([]ssh.AuthMethod, error) {
	var authMethods []ssh.AuthMethod
	if c.password != "" {
		authMethods = append(authMethods, ssh.Password(c.password))
	}
	if c.keyFile != "" {
		permBytes, err := os.ReadFile(c.keyFile)
		if err != nil {
			return nil, fmt.Errorf("ParseRawPrivateKey failed. " + err.Error())
		}
		key, err := ssh.ParseRawPrivateKey(permBytes)
		if err != nil {
			return nil, fmt.Errorf("ParseRawPrivateKey failed. " + err.Error())
		}
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			return nil, fmt.Errorf("NewSignerFromKey failed. " + err.Error())
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	return authMethods, nil
}

// RunCmdWithEnv 执行命令，携带环境变量
func (c *Cmd) RunCmdWithEnv(command string, envs map[string]string, mustEnv bool) *Result {
	return c.RunCmdWithEnvTimeout(command, envs, mustEnv, 0)
}
func (c *Cmd) RunCmdWithEnvTimeout(command string, envs map[string]string, mustEnv bool, timeout time.Duration) *Result {
	if len(envs) == 0 {
		return c.RunCmdTimeout(command, timeout)
	}
	glog.Info("run command [%s][timeout=%v] env %s", command, timeout, envs)

	session, err1 := c.client.NewSession()
	if err1 != nil {
		return &Result{command: command, err: fmt.Errorf("new session failed. " + err1.Error())}
	}
	defer session.Close()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	session.Stdout = stdout
	session.Stderr = stderr

	stdin, err := session.StdinPipe()
	if err != nil {
		return &Result{command: command, err: fmt.Errorf("session stdin pipe failed. " + err.Error())}
	}

	// 打开 shell
	if err = session.Shell(); err != nil {
		return &Result{command: command, err: err}
	}

	// 环境变量
	for name, value := range envs {
		if _, err = fmt.Fprintf(stdin, "export %s=%s\n", name, value); err != nil && mustEnv {
			return &Result{command: command, err: err}
		}
	}

	// 执行命令
	if _, err = fmt.Fprintf(stdin, "%s\n", command); err != nil {
		return &Result{command: command, err: err}
	}
	if err = stdin.Close(); err != nil {
		return &Result{command: command, err: err}
	}

	// 等待结果
	err = c.wait(timeout, func() error {
		return session.Wait()
	})
	return &Result{
		command: command,
		stdout:  strings.TrimSuffix(stdout.String(), "\n"),
		stderr:  strings.TrimSuffix(stderr.String(), "\n"),
		err:     err,
	}
}

// RunCmd 执行命令，不带环境变量
func (c *Cmd) RunCmd(command string) *Result {
	return c.RunCmdTimeout(command, 0)
}
func (c *Cmd) RunCmdTimeout(command string, timeout time.Duration) *Result {
	glog.Info("run command [%s][timeout=%v]", command, timeout)
	session, err1 := c.client.NewSession()
	if err1 != nil {
		return &Result{command: command, err: fmt.Errorf("new session failed. " + err1.Error())}
	}
	defer session.Close()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	session.Stdout = stdout
	session.Stderr = stderr
	err2 := c.wait(timeout, func() error {
		return session.Run(command)
	})
	return &Result{
		command: command,
		stdout:  strings.TrimSuffix(stdout.String(), "\n"),
		stderr:  strings.TrimSuffix(stderr.String(), "\n"),
		err:     err2,
	}
}

// PutData
// data: 支持传入字节或io.Reader
// file: 必须是文件
func (c *Cmd) PutData(data interface{}, file string, fileMode os.FileMode) (n int64, err error) {

	glog.Info("put data [%s]", file)
	if data == nil || file == "" {
		return 0, errors.New("put file failed. invalid data or file name")
	}

	// 创建client
	sftpClient, err := sftp.NewClient(c.client)
	if err != nil {
		return 0, fmt.Errorf("new sftp client error: %w", err)
	}
	defer sftpClient.Close()

	// 如果目录不存在则创建目录
	if dir, _ := filepath.Split(file); dir != "" {
		if _, err = sftpClient.Stat(dir); err != nil || !os.IsExist(err) {
			if err = sftpClient.MkdirAll(dir); err != nil {
				return 0, fmt.Errorf("mkdir %s failed: %w", dir, err)
			}
		}
	}

	// 创建文件
	target, err := sftpClient.Create(file)
	if err != nil {
		return 0, fmt.Errorf("sftp client open file %s error: %w", file, err)
	}
	defer target.Close()

	// 修改权限
	if fileMode != 0 {
		if err := target.Chmod(fileMode); err != nil {
			return 0, fmt.Errorf("chmod file %s failed: %w", file, err)
		}
	}

	// 数据传输
	switch data.(type) {
	case []byte:
		sb := &bytes.Buffer{}
		sb.Write(data.([]byte))
		n, err = io.Copy(target, sb)
	case io.Reader:
		n, err = io.Copy(target, data.(io.Reader))
	default:
		return 0, errors.New("data only support []byte or io.Reader")
	}
	if err != nil {
		return 0, fmt.Errorf("copy file %s error: %w", file, err)
	}
	return n, nil
}

// PutFile
// localPath: 本地文件或目录
// remotePath: 远程文件或目录
func (c *Cmd) PutFile(localPath, remotePath string) (err error) {

	glog.Info("put local file [%s -> %s]", localPath, remotePath)
	if localPath == "" || remotePath == "" {
		return errors.New("put file failed. invalid local filepath or remote filepath")
	}

	// 创建client
	sftpClient, err := sftp.NewClient(c.client)
	if err != nil {
		return fmt.Errorf("new sftp client error: %w", err)
	}
	defer sftpClient.Close()
	return c.putFile(localPath, remotePath, sftpClient)
}

func (c *Cmd) putFile(localPath, remotePath string, sftpClient *sftp.Client) error {

	srcFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open local file %s failed. %w", localPath, err)
	}
	defer srcFile.Close()

	stat, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("stat local file %s failed. %w", localPath, err)
	}

	if stat.IsDir() {
		files, err := srcFile.Readdir(0)
		if err != nil {
			return fmt.Errorf("read local dir %s failed. %w", localPath, err)
		}
		targetDir := filepath.Join(remotePath, stat.Name())
		glog.Info("remote mkdir [%s %s]", stat.Mode(), targetDir)
		sftpClient.MkdirAll(targetDir)
		sftpClient.Chmod(targetDir, stat.Mode())
		for _, file := range files {
			if err := c.putFile(filepath.Join(localPath, file.Name()), targetDir, sftpClient); err != nil {
				return err
			}
		}
		return nil
	}

	file := filepath.Join(remotePath, stat.Name())

	// 如果目录不存在则创建目录
	if dir, _ := filepath.Split(file); dir != "" {
		if _, err = sftpClient.Stat(dir); err != nil || !os.IsExist(err) {
			glog.Info("remote mkdir [%s]", dir)
			if err = sftpClient.MkdirAll(dir); err != nil {
				return fmt.Errorf("remote mkdir %s failed: %w", dir, err)
			}
		}
	}

	// 创建文件
	target, err := sftpClient.Create(file)
	if err != nil {
		return fmt.Errorf("sftp client open remote file %s error: %w", file, err)
	}
	defer target.Close()

	glog.Info("remote create file [%s %s]", stat.Mode(), file)

	// 修改权限
	if err := target.Chmod(stat.Mode()); err != nil {
		return fmt.Errorf("chmod remote file %s failed: %w", file, err)
	}

	// 数据传输
	_, err = io.Copy(target, srcFile)
	if err != nil {
		return fmt.Errorf("copy to remote file %s error: %w", file, err)
	}
	return nil
}

// GetFile
// remoteFile 下载远程文件或目录
// createDir  如果远程是目录，则回调进行本地目录创建
// getWriter  如果远程是文件，则回调进行数据传输，传输到的本地目标可以自己控制，可以是文件，也可以是内存缓存等等
func (c *Cmd) GetFile(remoteFile string, createDir func(remoteFile string, fileInfo os.FileInfo) error, getWriter func(remoteFile string, fileInfo os.FileInfo) (*Writer, error)) (err error) {

	glog.Info("get remote file [%s]", remoteFile)
	if remoteFile == "" || createDir == nil {
		return errors.New("get file failed. invalid file name or createDir func")
	}

	// 创建client
	sftpClient, err := sftp.NewClient(c.client)
	if err != nil {
		return fmt.Errorf("new sftp client error: %w", err)
	}
	defer sftpClient.Close()
	return c.getFile(remoteFile, sftpClient, createDir, getWriter)
}

func (c *Cmd) getFile(remoteFile string, sftpClient *sftp.Client, createDir func(remoteFile string, fileInfo os.FileInfo) error, getWriter func(remoteFile string, fileInfo os.FileInfo) (*Writer, error)) error {

	// 打开文件
	sourceFile, err := sftpClient.Open(remoteFile)
	if err != nil {
		return fmt.Errorf("sftp client open remote file %s error: %w", remoteFile, err)
	}
	defer sourceFile.Close()

	// 文件信息
	stat, err := sourceFile.Stat()
	if err != nil {
		return fmt.Errorf("stat remote file %s failed. %w", remoteFile, err)
	}

	// 目录
	if stat.IsDir() {
		if err = createDir(remoteFile, stat); err != nil {
			return err
		}
		files, err := sftpClient.ReadDir(remoteFile)
		if err != nil {
			return fmt.Errorf("read remote dir %s failed. %w", remoteFile, err)
		}
		for _, f := range files {
			if err = c.getFile(filepath.Join(remoteFile, f.Name()), sftpClient, createDir, getWriter); err != nil {
				return err
			}
		}
		return nil
	}

	// 数据传输
	out, err := getWriter(remoteFile, stat)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err = io.Copy(out, sourceFile); err != nil {
		return fmt.Errorf("copy remote file %s error: %w", remoteFile, err)
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////

type Result struct {
	command string
	stdout  string
	stderr  string
	err     error
}

func (r *Result) HasError(printDetailWhenError bool) bool {
	hasErr := r.err != nil
	if printDetailWhenError {
		if hasErr {
			glog.Error("[command=%s]. detail=%s", r.command, r.Detail())
		} else if r.stderr != "" {
			glog.Warning("[command=%s]. detail=%s", r.command, r.Detail())
		}
	}
	return hasErr
}

func (r *Result) Detail() string {
	return fmt.Sprintf("[stdout=%s] [stderr=%s] [exit=%v]", r.GetStdout(), r.GetStderr(), r.err)
}

func (r *Result) ErrInfo() string {
	return fmt.Sprintf("[stdout=%s] [stderr=%s] [exit=%v]", r.GetStdout(), r.GetStderr(), r.err)
	//	if r.stderr != "" {
	//		return r.stderr
	//	}
	//	if r.err != nil {
	//		return r.err.Error()
	//	}
	//	if r.stdout != "" {
	//		return r.stdout
	//	}
	//	return ""
}

func (r *Result) IsExit0() bool {
	return r.err == nil
}

func (r *Result) GetCommand() string {
	return r.command
}
func (r *Result) GetStdout() string {
	return r.stdout
}
func (r *Result) GetStderr() string {
	return r.stderr
}

////////////////////////////////////////////////////////////////////////////////////////////////////

type Writer struct {
	io.Writer
	CleanFunc func()
}

func (w *Writer) Close() {
	w.CleanFunc()
}

////////////////////////////////////////////////////////////////////////////////////////////////////

// Conn wraps a net.Conn, and sets a deadline for every read  and write operation.
type Conn struct {
	net.Conn
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

func (c *Conn) Read(b []byte) (int, error) {
	err := c.Conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
	if err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	err := c.Conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
	if err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

func (c *Cmd) wait(timeout time.Duration, f func() error) (err error) {
	if timeout == 0 {
		return f()
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		err = f()
		cancel()
	}()
	select {
	case <-ctx.Done():
	case <-time.After(timeout):
		err = errors.New("command is timeout") //超时
	}
	return err
}
