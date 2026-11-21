package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/gharut/torinator/internal/versioning"
)

func main() {
	bump := flag.String("bump", "patch", "patch, minor or major")
	flag.Parse()
	data, err := exec.Command("git", "tag", "--list").Output()
	if err == nil {
		var next string
		next, err = versioning.Next(strings.Fields(string(data)), *bump)
		if err == nil {
			fmt.Println(next)
			return
		}
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
