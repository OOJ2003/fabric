package util

import (
	"log"
	"strconv"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func sha2256tpm(data []byte) ([]byte, error) {

	persistentHandle, _ := strconv.ParseUint("0x81010002", 0, 32)

	rwc, err := tpm2.OpenTPM()
	if err != nil {
		log.Fatalf("can't open TPM: %v", err)
	}
	defer rwc.Close()

	kh := tpmutil.Handle(uint32(persistentHandle))
	defer tpm2.FlushContext(rwc, kh)

	khDigest, _, err := tpm2.Hash(rwc, tpm2.AlgSHA256, data, tpm2.HandleOwner)

	return khDigest, err
}

func sha3256tpm(data []byte) ([]byte, error) {
	persistentHandle, _ := strconv.ParseUint("0x81010002", 0, 32)
	rwc, err := tpm2.OpenTPM()
	if err != nil {
		log.Fatalf("can't open TPM : %v", err)
	}
	defer rwc.Close()

	kh := tpmutil.Handle(uint32(persistentHandle))
	defer tpm2.FlushContext(rwc, kh)

	khDigest, _, err := tpm2.Hash(rwc, tpm2.AlgSHA3_256, data, tpm2.HandleOwner)

	return khDigest, err
}
