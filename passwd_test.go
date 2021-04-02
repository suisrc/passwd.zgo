package passwd_test

import (
	"encoding/json"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/suisrc/crypto.zgo"
	"github.com/suisrc/passwd.zgo"
)

func TestBcrypt(t *testing.T) {
	pwd, err := passwd.GenerateBcrypt("123456", "BCR")
	assert.Nil(t, err)
	byt, err := json.Marshal(pwd)
	log.Println(string(byt))
	pwx := &PasswdX{
		GeneratePasswd: *pwd,
		PasswordX:      "123456",
	}
	res, err := passwd.VerifyBcrypt(pwx)
	assert.Nil(t, err)
	assert.True(t, res)
}

func TestBcrypt2(t *testing.T) {
	pwd, err := passwd.GenerateBcrypt2("123456", "BCR")
	assert.Nil(t, err)
	byt, err := json.Marshal(pwd)
	log.Println(string(byt))
	pwx := &PasswdX{
		GeneratePasswd: *pwd,
		PasswordX:      "123456",
	}
	res, err := passwd.VerifyBcrypt2(pwx)
	assert.Nil(t, err)
	assert.True(t, res)
}

func TestBcrypt3(t *testing.T) {
	pwd, err := passwd.GenerateBcrypt3("123456", "BCR")
	assert.Nil(t, err)
	byt, err := json.Marshal(pwd)
	log.Println(string(byt))
	pwx := &PasswdX{
		GeneratePasswd: *pwd,
		PasswordX:      "123456",
	}
	res, err := passwd.VerifyBcrypt3(pwx)
	assert.Nil(t, err)
	assert.True(t, res)
}

func TestMD5(t *testing.T) {
	pwd, err := passwd.GenerateMD5("123456", "MD5")
	assert.Nil(t, err)
	byt, err := json.Marshal(pwd)
	log.Println(string(byt))
	pwx := &PasswdX{
		GeneratePasswd: *pwd,
		PasswordX:      "123456",
	}
	res, err := passwd.VerifyMD5(pwx)
	assert.Nil(t, err)
	assert.True(t, res)
}

func TestSHA1(t *testing.T) {
	pwd, err := passwd.GenerateSHA1("123456", "SHA1")
	assert.Nil(t, err)
	byt, err := json.Marshal(pwd)
	log.Println(string(byt))
	pwx := &PasswdX{
		GeneratePasswd: *pwd,
		PasswordX:      "123456",
	}
	res, err := passwd.VerifySHA1(pwx)
	assert.Nil(t, err)
	assert.True(t, res)
}

type PasswdX struct {
	passwd.GeneratePasswd
	PasswordX string
}

func (a *PasswdX) Target() string {
	return a.PasswordX
}

// 测试速度
func TestMD5Speed(t *testing.T) {

	for i := 10000; i > 0; i-- {
		pwo := crypto.UUID(16)
		pwd, _ := passwd.GenerateMD5(pwo, "MD5")
		pwx := &PasswdX{
			GeneratePasswd: *pwd,
			PasswordX:      pwo,
		}
		passwd.VerifyMD5(pwx)
	}

	assert.True(t, true)
}

// 测试速度
func TestSHA1Speed(t *testing.T) {

	for i := 10000; i > 0; i-- {
		pwo := crypto.UUID(16)
		pwd, _ := passwd.GenerateSHA1(pwo, "SHA1")
		pwx := &PasswdX{
			GeneratePasswd: *pwd,
			PasswordX:      pwo,
		}
		passwd.VerifySHA1(pwx)
	}

	assert.True(t, true)
}

// 测试速度
func TestBCR0Speed(t *testing.T) {

	for i := 10; i > 0; i-- {
		pwo := crypto.UUID(16)
		pwd, _ := passwd.GenerateBcrypt(pwo, "BCR")
		pwx := &PasswdX{
			GeneratePasswd: *pwd,
			PasswordX:      pwo,
		}
		passwd.VerifyBcrypt(pwx)
	}

	assert.True(t, true)
}
