package main

import (
	"KYSA/db"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	exe, err := os.Executable()
	if err != nil {
		panic(err)
	}

	projectDir := filepath.Dir(filepath.Dir(exe))

	pageSize := 394

	for i := 1; i <= pageSize; i++ {
		reports := db.ParsePage(i)
		fmt.Fprintf(os.Stderr, "page %v\n", i)
		time.Sleep(time.Duration(100) * time.Millisecond)
		for j := range reports {
			detail := db.ParseKYSAReport(&reports[j])
			fmt.Fprintf(os.Stderr, "item %v\n", j)
			fixName := strings.ReplaceAll(detail.Name, "/", "_")
			err = os.WriteFile(filepath.Join(projectDir, "output", fixName), []byte(detail.String()), 0644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "writeFile(%s) failed with %v\n", filepath.Join(projectDir, "output", fixName), err)
			}
			time.Sleep(time.Duration(100) * time.Millisecond)
		}
	}
}
