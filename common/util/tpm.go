package util

import (
	"log"
	"os"
	"strconv"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/joho/godotenv"
)

func sha2256tpm(data []byte) ([]byte, error) {
	err := godotenv.Load("/home/lazydoge/blockchain_tpm/.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	tpmPath := os.Getenv("TPM_DEVICE")
	keyHandle := os.Getenv("HANDLE")

	persistentHandle, _ := strconv.ParseUint(keyHandle, 0, 32)

	rwc, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}
	defer rwc.Close()

	kh := tpmutil.Handle(uint32(persistentHandle))
	defer tpm2.FlushContext(rwc, kh)

	dataToSign := []byte("hello")
	khDigest, _, err := tpm2.Hash(rwc, tpm2.AlgSHA256, dataToSign, tpm2.HandleOwner)

	return khDigest, err
}

func sha3256tpm(data []byte) ([]byte, error) {
	err := godotenv.Load("/home/lazydoge/blockchain_tpm/.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	tpmPath := os.Getenv("TPM_DEVICE")
	keyHandle := os.Getenv("HANDLE")

	persistentHandle, _ := strconv.ParseUint(keyHandle, 0, 32)

	rwc, err := tpm2.OpenTPM(tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", tpmPath, err)
	}
	defer rwc.Close()

	kh := tpmutil.Handle(uint32(persistentHandle))
	defer tpm2.FlushContext(rwc, kh)

	dataToSign := []byte("hello")
	khDigest, _, err := tpm2.Hash(rwc, tpm2.AlgSHA3_256, dataToSign, tpm2.HandleOwner)

	return khDigest, err
}
