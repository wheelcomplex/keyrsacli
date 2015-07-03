//

//key base rsa crypt command line tool

package main

import (
	"os"
	"time"

	"github.com/wheelcomplex/preinit/getopt"
	"github.com/wheelcomplex/preinit/keyrsa"
	"github.com/wheelcomplex/preinit/misc"
)

var opt = getopt.Opt
var tpf = misc.Tpf

func main() {
	go misc.GoHttpProfile("localhost:6090")
	time.Sleep(1e8)

	key := opt.OptVarString("-k/--key", "2.71828182845904523536028747135266249775724709369995957496696762", "input key string")
	rsalen := opt.OptVarInt("-l/--lenght", "2k", "rsa key lenght")
	size := opt.OptVarInt("-s/--size", "256", "size of plain text")
	cpus := opt.OptVarInt("-c/--cpu", "-1", "running cpus")
	//workers := opt.OptVarInt("-w/--worker", "0", "number of aes worker")
	loop := opt.OptVarInt("-l/--loop", "1m", "number of stress loop")
	//vb := opt.OptVarBool("-v/--verb", "false", "debug")

	if opt.OptVarBool("-h/--help", "false", "show help") {
		opt.Usage()
		os.Exit(9)
	}
	if size < 0 {
		opt.Usage()
		os.Exit(1)
	}
	starts := time.Now()
	prets := starts

	enRc := keyrsa.NewKeyRSACrypto([]byte(key), rsalen)
	deRc := keyrsa.NewKeyRSACrypto([]byte(key), rsalen)

	misc.Tpf("%d cpus, payload size %d, stress loop %d\n", misc.SetGoMaxCPUs(cpus), size, loop)
	plaintext := enRc.GetBuf(size)
	//	for i := 0; i < 1000; i++ {
	misc.MemSetBytes(plaintext, 255)
	misc.Tpf("MemSetBytes, frame size %d, %v\n", len(plaintext), time.Now().Sub(prets))
	prets = time.Now()

	osum := enRc.Sum(plaintext)
	ohash := enRc.Hash(plaintext)
	osign, oerr := enRc.SignOrigPKCS1v15(plaintext)
	if oerr != nil {
		tpf("%s\n", oerr.Error())
		os.Exit(1)
	}
	overify := enRc.VerifyOrigPKCS1v15(plaintext, osign)

	displen := len(plaintext)
	if displen > 16 {
		displen = 16
	}
	misc.Tpf("sign, %v\n", time.Now().Sub(prets))
	prets = time.Now()
	tpf("keyrsa:\n")
	tpf("\t Key(%d): %s\n", len(key), key)
	tpf("\t Txt(%d): %v\n", len(plaintext), plaintext[:displen])
	//   kr := keyrsa.NewKeyRSA([]byte(key), rsalen)
	//	tpf("\t PrivatePEM(%d): \n%s\n", len(kr.PrivatePEM()), kr.PrivatePEM())
	//	tpf("\t PublicPEM(%d): \n%s\n", len(kr.PublicPEM()), kr.PublicPEM())
	tpf("\t Sign(%d): %v\n", len(osign), osign)
	overifystat := "true"
	if overify != nil {
		overifystat = overify.Error()
	}
	misc.Tpf("verify, %v\n", time.Now().Sub(prets))
	prets = time.Now()
	tpf("\t Verify(%v): %v\n", overifystat, overifystat)
	prets = time.Now()
	ciphertext, err := enRc.NonceEncrypt(plaintext)
	if err != nil {
		tpf("%s\n", err.Error())
		os.Exit(1)
	}
	misc.Tpf("Encrypt, %v\n", time.Now().Sub(prets))
	prets = time.Now()
	displen = len(ciphertext)
	if displen > 16 {
		displen = 16
	}
	tpf("\t Encrypt(%d): %v\n", len(ciphertext), ciphertext[:displen])
	prets = time.Now()
	msg, err := deRc.NonceDecrypt(ciphertext)
	if err != nil {
		tpf("%s\n", err.Error())
		os.Exit(1)
	}
	misc.Tpf("Decrypt, %v\n", time.Now().Sub(prets))
	prets = time.Now()
	dsum := deRc.Sum(plaintext)
	dhash := deRc.Hash(plaintext)
	displen = len(msg)
	if displen > 16 {
		displen = 16
	}
	tpf("\t Decrypt(%d): %v\n", len(msg), msg[:displen])
	tpf("\t OHash(%d): %d, %v\n", len(osum), ohash, osum)
	tpf("\t DHash(%d): %d, %v\n", len(dsum), dhash, dsum)
	if ohash != dhash {
		tpf("Encrypt/Decrypt hash mismatch\n")
	}
	//	//
	//	for i := 0; i < 10; i++ {
	//		ciphertext, err = enRc.NonceEncrypt(plaintext)
	//		if err != nil {
	//			tpf("%s\n", err.Error())
	//			os.Exit(1)
	//		}
	//		enRc.PutBuf(ciphertext)
	//	}
	//	misc.Tpf("NonceEncrypt X 10, %v\n", time.Now().Sub(prets))
	//	ciphertext, err = enRc.NonceEncrypt(plaintext)
	//	prets = time.Now()
	//	for i := 0; i < 10; i++ {
	//		msg, err = deRc.NonceDecrypt(ciphertext)
	//		if err != nil {
	//			tpf("%s\n", err.Error())
	//			os.Exit(1)
	//		}
	//		deRc.PutBuf(msg)
	//	}
	//	misc.Tpf("NonceDecrypt X 10, %v\n", time.Now().Sub(prets))
	//	prets = time.Now()

	misc.Tpf("stress test, %d loops\n", loop)
	prets = time.Now()
	loopts := prets
	for i := 0; i < loop; i++ {
		ciphertext, err = enRc.NonceEncrypt(plaintext)
		if err != nil {
			tpf("%s\n", err.Error())
			os.Exit(1)
		}
		msg, err = deRc.NonceDecrypt(ciphertext)
		if err != nil {
			tpf("%s\n", err.Error())
			os.Exit(1)
		}
		enRc.PutBuf(ciphertext)
		deRc.PutBuf(msg)
	}
	esp := time.Now().Sub(loopts)
	qps := uint64(loop) * uint64(time.Second) / uint64(esp)
	misc.Tpf("stress: qps %d(%s), esp %v\n", qps, misc.ItoKMG(int(qps)), esp)
}
