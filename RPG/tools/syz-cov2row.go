// file: read_corpus.go
package main

import (
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
)

// CorpusInfo must match the struct shape used for encoding.
// Make sure the fields are exported and spelled exactly the same as in the writer.
type CorpusInfo struct {
	Prog   []byte
	Signal interface{} // or the actual type if you have a custom type
	Cover  []uint32
}

func main() {
	// Expect two args: <vmlinuxPath> <corpusDataPath>
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <path to vmlinux> <path to corpus_data.gob>\n", os.Args[0])
		os.Exit(1)
	}
	vmlinuxPath := os.Args[1]
	corpusPath := os.Args[2]

	// 1. Open the corpus_data.gob file for reading
	file, err := os.Open(corpusPath)
	if err != nil {
		log.Fatalf("Error opening gob file %q: %v", corpusPath, err)
	}
	defer file.Close()

	// 2. Create a new gob Decoder
	decoder := gob.NewDecoder(file)

	// 3. Read entries in a loop until we reach EOF
	for {
		var item CorpusInfo
		if err := decoder.Decode(&item); err != nil {
			if err == io.EOF {
				// We've reached the end of the file
				break
			}
			log.Fatalf("Error decoding gob: %v", err)
		}

		// Print the contents of this CorpusInfo entry
		fmt.Printf("corpus: saving program %v\n", string(item.Prog))

		// For each address in Cover, run address2line to map to file:line in vmlinux
		for _, addr := range item.Cover {
			addrHex := fmt.Sprintf("ffffffff%x", addr)
			cmd := exec.Command("addr2line", "-e", vmlinuxPath, addrHex)
			out, cmdErr := cmd.CombinedOutput()
			if cmdErr != nil {
				log.Printf("addr2line failed for %s: %v\n", addrHex, cmdErr)
				continue
			}
			fmt.Printf("cover address %s => %s", addrHex, out)
		}

		fmt.Println() // Blank line separating each CorpusInfo
	}
}
