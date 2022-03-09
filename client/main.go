package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/avegner/cli"
	"github.com/avegner/passwd_manager/generator"
	"github.com/avegner/passwd_manager/storage"
	"golang.org/x/term"
)

const (
	storagePath = "/home/alekseivegner/.passwd_db"
	noncePath   = "/home/alekseivegner/.nonce"
)

func main() {
	c := cli.New(
		cli.WithCommand("list", "list all labels", 0, listCmd),
		cli.WithCommand("show", "show password", 1, showCmd),
		cli.WithCommand("add", "generate password", 2, addCmd),
		cli.WithCommand("remove", "remove password", 1, removeCmd),
		cli.WithCommand("update-key", "update encryption key", 0, updateKeyCmd))

	if err := c.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func listCmd(opts cli.OptionMap, _ []string) error {
	st, _, err := readDB()
	if err != nil {
		return err
	}

	for _, l := range st.List() {
		fmt.Println(" * ", l)
	}
	return nil
}

func showCmd(opts cli.OptionMap, args []string) error {
	st, _, err := readDB()
	if err != nil {
		return err
	}

	label := args[0]
	passwd, err := st.Get(label)
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, passwd)
	return nil
}

func addCmd(opts cli.OptionMap, args []string) error {
	st, dbPasswd, err := readDB()
	if err != nil {
		return err
	}

	label := args[0]
	leng, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil {
		return err
	}

	passwd, err := generator.Generate(uint(leng))
	if err != nil {
		return err
	}

	fmt.Println(passwd)
	st.Put(label, passwd)

	return updateDB(st, dbPasswd)
}

func removeCmd(opts cli.OptionMap, args []string) error {
	st, dbPasswd, err := readDB()
	if err != nil {
		return err
	}

	label := args[0]
	if err := st.Remove(label); err != nil {
		return err
	}
	return updateDB(st, dbPasswd)
}

func updateKeyCmd(opts cli.OptionMap, args []string) error {
	st, old, err := readDB()
	if err != nil {
		return err
	}

	new1, err := getDBKey("new")
	new2, err := getDBKey("repeat new")
	if string(new1) != string(new2) {
		return errors.New("keys don't match")
	}

	if string(old) == string(new1) {
		return errors.New("new and old keys are the same")
	}

	return updateDB(st, new1)
}

func getDBKey(prefix ...string) ([]byte, error) {
	if len(prefix) > 0 {
		fmt.Printf("%s ", prefix[0])
	}
	fmt.Printf("key: ")

	key, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	if err != nil {
		return nil, err
	}
	if len(key) == 0 {
		return nil, errors.New("empty key")
	}

	return key, nil
}

func readStorage(key []byte) (*storage.Storage, error) {
	blob, err := ioutil.ReadFile(storagePath)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	nonce, err := ioutil.ReadFile(noncePath)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	return storage.New(blob, nonce, key)
}

func readDB() (st *storage.Storage, key []byte, err error) {
	key, err = getDBKey()
	if err != nil {
		return nil, nil, err
	}

	st, err = readStorage(key)
	if err != nil {
		return nil, nil, err
	}
	return st, key, nil
}

func updateDB(st *storage.Storage, passwd []byte) error {
	blob, nonce, err := st.Encrypt([]byte(passwd))
	if err != nil {
		return err
	}

	if err = ioutil.WriteFile(noncePath, nonce, 0600); err != nil {
		return err
	}
	return ioutil.WriteFile(storagePath, blob, 0600)
}
