//

//key base rsa crypt command line tool

package main

import (
	"os"
	"time"

	"github.com/wheelcomplex/preinit/getopt"
	"github.com/wheelcomplex/preinit/keyaes"
	"github.com/wheelcomplex/preinit/keyrsa"
	"github.com/wheelcomplex/preinit/misc"
)

var opt = getopt.Opt
var tpf = misc.Tpf

func main() {
	go misc.GoHttpProfile("localhost:6090")
	time.Sleep(1e8)

	key := opt.OptVarString("-k/--key", "2.71828182845904523536028747135266249775724709369995957496696762", "input key string")
	rsalen := opt.OptVarInt("-r/--lenght", "2k", "rsa key lenght")
	size := opt.OptVarInt("-s/--size", "256", "size of plain text")
	cpus := opt.OptVarInt("-c/--cpu", "-1", "running cpus")
	//workers := opt.OptVarInt("-w/--worker", "0", "number of aes worker")
	loop := opt.OptVarInt("-l/--loop", "0", "number of stress loop")
	looptype := opt.OptVarInt("-t/--type", "0", "type of stress loop, 0 for all, 1 for encrypt, 2 for decrypt")
	//vb := opt.OptVarBool("-v/--verb", "false", "debug")

	if opt.OptVarBool("-h/--help", "false", "show help") {
		opt.Usage()
		os.Exit(9)
	}
	if size < 0 {
		opt.Usage()
		os.Exit(1)
	}
	cpus = misc.SetGoMaxCPUs(cpus)
	starts := time.Now()
	prets := starts

	enRc := keyrsa.NewKeyRSACrypto([]byte(key), rsalen, cpus)
	deRc := keyrsa.NewKeyRSACrypto([]byte(key), rsalen, cpus)

	misc.Tpf("%d cpus, payload size %d, stress loop %d\n", cpus, size, loop)
	plaintext := enRc.GetBuf(size)
	//	for i := 0; i < 1000; i++ {
	misc.MemSetBytes(plaintext, 255)
	misc.Tpf("MemSetBytes, frame size %d, %v\n", len(plaintext), time.Now().Sub(prets))
	prets = time.Now()

	osum := enRc.Sum(plaintext)
	ohash := enRc.Hash(plaintext)
	osign, oerr := enRc.SignOrigPKCS1v15(plaintext)
	if oerr != nil {
		tpf("SignOrigPKCS1v15: %s\n", oerr.Error())
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
		tpf("NonceEncrypt: %s\n", err.Error())
		os.Exit(1)
	}
	rsaenEsp := time.Now().Sub(prets)
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
		tpf("NonceDecrypt: %s\n", err.Error())
		os.Exit(1)
	}
	rsadeEsp := time.Now().Sub(prets)
	misc.Tpf("Decrypt, %v\n", time.Now().Sub(prets))
	prets = time.Now()
	dsum := deRc.Sum(msg)
	dhash := deRc.Hash(msg)
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
	deRc.PutBuf(msg)

	// try aes

	aesEn := keyaes.NewEncryptAES([]byte(key), nil, cpus)
	aesDe := keyaes.NewDecryptAES([]byte(key), nil, cpus)
	prets = time.Now()
	aesframe := aesEn.Encrypt(nil, plaintext)
	displen = len(aesframe)
	if displen > 16 {
		displen = 16
	}
	aesenEsp := time.Now().Sub(prets)
	misc.Tpf("AesEncrypt, %v\n", time.Now().Sub(prets))
	tpf("\t AesEncrypt(%d): %v\n", len(aesframe), aesframe[:displen])
	prets = time.Now()
	aesplaintext, err := aesDe.Decrypt(aesframe)
	if err != nil {
		tpf("AES Decrypt: %s\n", err.Error())
		os.Exit(1)
	}
	aesdeEsp := time.Now().Sub(prets)
	displen = len(aesframe)
	if displen > 16 {
		displen = 16
	}
	misc.Tpf("AesDecrypt, %v\n", time.Now().Sub(prets))
	tpf("\t AesDecrypt(%d): %v\n", len(aesplaintext), aesplaintext[:displen])
	prets = time.Now()
	aesEnhash := keyaes.Murmur3Sum32(plaintext)
	aesDehash := keyaes.Murmur3Sum32(aesplaintext)
	tpf("\t aesEnhash: %d\n", aesEnhash)
	tpf("\t aesEnhash: %d\n", aesEnhash)
	if aesEnhash != aesDehash {
		tpf("AES Encrypt/Decrypt hash mismatch\n")
	}
	tpf("\t Encrypt RSA/AES: %d / %d = %d(%s)\n", rsaenEsp, aesenEsp, rsaenEsp/aesenEsp, misc.ItoKMG(int(rsaenEsp/aesenEsp)))
	tpf("\t Decrypt RSA/AES: %d / %d = %d(%s)\n", rsadeEsp, aesdeEsp, rsadeEsp/aesdeEsp, misc.ItoKMG(int(rsadeEsp/aesdeEsp)))
	tpf("\t RSA Decrypt/Encrypt: %d / %d = %d(%s)\n", rsadeEsp, rsaenEsp, rsadeEsp/rsaenEsp, misc.ItoKMG(int(rsadeEsp/rsaenEsp)))
	aesEn.PutBuf(aesframe)
	aesDe.PutBuf(aesplaintext)

	if loop > 0 {
		prets = time.Now()
		loopts := prets
		var esp time.Duration
		var qps uint64
		if looptype == 2 || looptype == 0 {
			misc.Tpf("Decrypt stress test, %d loops\n", loop)
			for i := 0; i < loop; i++ {
				msg, err = deRc.NonceDecrypt(ciphertext)
				if err != nil {
					tpf("NonceDecrypt: %s\n", err.Error())
					os.Exit(1)
				}
				deRc.PutBuf(msg)
			}
			esp = time.Now().Sub(loopts)
			qps = uint64(loop) * uint64(time.Second) / uint64(esp)
			misc.Tpf("Decrypt stress: qps %d(%s), esp %v\n", qps, misc.ItoKMG(int(qps)), esp)
		}
		enRc.PutBuf(ciphertext)
		prets = time.Now()
		loopts = prets
		if looptype == 1 || looptype == 0 {
			misc.Tpf("Encrypt stress test, %d loops\n", loop)
			for i := 0; i < loop; i++ {
				ciphertext, err = enRc.NonceEncrypt(plaintext)
				if err != nil {
					tpf("NonceEncrypt: %s\n", err.Error())
					os.Exit(1)
				}
				enRc.PutBuf(ciphertext)
			}
			esp = time.Now().Sub(loopts)
			qps = uint64(loop) * uint64(time.Second) / uint64(esp)
			misc.Tpf("Encrypt stress: qps %d(%s), esp %v\n", qps, misc.ItoKMG(int(qps)), esp)
		}
	}
}
