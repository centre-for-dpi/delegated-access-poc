package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

const BitstringSize = 16384 // 131072 bits = 16384 bytes (W3C minimum)

type Bitstring struct {
	mu       sync.RWMutex
	bits     []byte
	filePath string
	nextIdx  int
	idxFile  string
}

func NewBitstring(filePath string) *Bitstring {
	bs := &Bitstring{
		bits:     make([]byte, BitstringSize),
		filePath: filePath,
		idxFile:  filePath + ".idx",
	}

	dir := filepath.Dir(filePath)
	os.MkdirAll(dir, 0755)

	if data, err := os.ReadFile(filePath); err == nil && len(data) == BitstringSize {
		bs.bits = data
		log.Printf("Loaded persisted bitstring from %s", filePath)
	} else {
		log.Printf("Initialized fresh bitstring (%d bytes)", BitstringSize)
	}

	if data, err := os.ReadFile(bs.idxFile); err == nil {
		var idx int
		if _, err := fmt.Sscanf(string(data), "%d", &idx); err == nil {
			bs.nextIdx = idx
			log.Printf("Loaded next index: %d", idx)
		}
	}

	return bs
}

func (bs *Bitstring) SetBit(index int) bool {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if index < 0 || index >= BitstringSize*8 {
		return false
	}
	byteIndex := index / 8
	bitIndex := 7 - (index % 8)
	bs.bits[byteIndex] |= 1 << uint(bitIndex)
	bs.persist()
	return true
}

func (bs *Bitstring) ClearBit(index int) bool {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if index < 0 || index >= BitstringSize*8 {
		return false
	}
	byteIndex := index / 8
	bitIndex := 7 - (index % 8)
	bs.bits[byteIndex] &^= 1 << uint(bitIndex)
	bs.persist()
	return true
}

func (bs *Bitstring) GetBit(index int) bool {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	if index < 0 || index >= BitstringSize*8 {
		return false
	}
	byteIndex := index / 8
	bitIndex := 7 - (index % 8)
	return (bs.bits[byteIndex] & (1 << uint(bitIndex))) != 0
}

func (bs *Bitstring) Encode() (string, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(bs.bits); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}

	encoded := "u" + base64.RawURLEncoding.EncodeToString(buf.Bytes())
	return encoded, nil
}

func (bs *Bitstring) AllocateIndex() int {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	idx := bs.nextIdx
	bs.nextIdx++
	bs.persistIndex()
	return idx
}

func (bs *Bitstring) persist() {
	if err := os.WriteFile(bs.filePath, bs.bits, 0644); err != nil {
		log.Printf("WARNING: failed to persist bitstring: %v", err)
	}
}

func (bs *Bitstring) persistIndex() {
	data := fmt.Sprintf("%d", bs.nextIdx)
	if err := os.WriteFile(bs.idxFile, []byte(data), 0644); err != nil {
		log.Printf("WARNING: failed to persist index counter: %v", err)
	}
}
