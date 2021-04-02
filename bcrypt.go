package passwd

import (
	"strings"

	"github.com/suisrc/crypto.zgo"
)

// VerifyBcrypt bcrypt
func VerifyBcrypt(ent IEntity) (bool, error) {
	hashpass := ent.Salt() + ent.Source()
	err := crypto.CompareHashAndPassword([]byte(hashpass), []byte(ent.Target()))
	if err != nil {
		return false, err
	}
	return true, nil
}

// GenerateBcrypt bcrypt
func GenerateBcrypt(password string, ptype string) (*GeneratePasswd, error) {
	pwd, err := crypto.GenerateFromPassword([]byte(password), bCost)
	if err != nil {
		return nil, err
	}
	pwdstr := string(pwd)
	// $ver$cost$[salte:22]hashpass
	offset := strings.LastIndex(pwdstr, "$") + 22
	return &GeneratePasswd{
		Password:     pwdstr[offset:],
		PasswordType: ptype,
		PasswordSalt: pwdstr[:offset],
	}, nil
}

// VerifyBcrypt2 bcrypt
func VerifyBcrypt2(ent IEntity) (bool, error) {
	salt, err := crypto.Base64DecodeString(ent.Salt())
	if err != nil {
		return false, nil
	}
	hashpass := crypto.Reverse(string(salt)) + ent.Source()
	err = crypto.CompareHashAndPassword([]byte(hashpass), []byte(ent.Target()))
	if err != nil {
		return false, err
	}
	return true, nil
}

// GenerateBcrypt2 bcrypt
func GenerateBcrypt2(password string, ptype string) (*GeneratePasswd, error) {
	pwd, err := crypto.GenerateFromPassword([]byte(password), 9)
	if err != nil {
		return nil, err
	}
	pwdstr := string(pwd)
	// $ver$cost$[salte:22]hashpass
	offset := strings.LastIndex(pwdstr, "$") + 22
	salt := crypto.Base64EncodeToString([]byte(crypto.Reverse(pwdstr[:offset])))
	return &GeneratePasswd{
		Password:     pwdstr[offset:],
		PasswordType: ptype,
		PasswordSalt: salt,
	}, nil
}

// VerifyBcrypt3 bcrypt
func VerifyBcrypt3(ent IEntity) (bool, error) {
	salx, err := crypto.Base64DecodeString(ent.Salt())
	if err != nil {
		return false, nil
	}
	sbyt := crypto.MaskDecrypt(salx, []byte(ent.Source()))
	salt := string(sbyt)
	hashpass := salt + ent.Source()
	err = crypto.CompareHashAndPassword([]byte(hashpass), []byte(ent.Target()))
	if err != nil {
		return false, err
	}
	return true, nil
}

// GenerateBcrypt3 bcrypt
func GenerateBcrypt3(password string, ptype string) (*GeneratePasswd, error) {
	pwd, err := crypto.GenerateFromPassword([]byte(password), 9)
	if err != nil {
		return nil, err
	}
	pwdstr := string(pwd)
	// $ver$cost$[salte:22]hashpass
	offset := strings.LastIndex(pwdstr, "$") + 22
	salt := pwdstr[:offset]
	rpwd := pwdstr[offset:]
	sbyt := crypto.MaskEncrypt([]byte(salt), []byte(rpwd))
	salx := crypto.Base64EncodeToString(sbyt)
	return &GeneratePasswd{
		Password:     rpwd,
		PasswordType: ptype,
		PasswordSalt: salx,
	}, nil
}
