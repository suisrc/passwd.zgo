package passwd

import (
	"github.com/suisrc/crypto.zgo"
)

// VerifyMD5 bcrypt
func VerifyMD5(ent IEntity) (bool, error) {
	epwd := crypto.MaskEncrypt([]byte(ent.Target()), []byte(ent.Salt()))
	pwds := crypto.MD5Hash(epwd)
	for i := mCost; i > 0; i-- {
		pwds = crypto.MD5HashString(pwds)
	}
	return ent.Source() == pwds, nil
}

// GenerateMD5 bcrypt
func GenerateMD5(password string, ptype string) (*GeneratePasswd, error) {
	salt := crypto.UUID(32)
	// pwdx := password + "$" + salt // 是否需要拉长密码?进行补位?待定
	epwd := crypto.MaskEncrypt([]byte(password), []byte(salt))
	pwds := crypto.MD5Hash(epwd)
	for i := mCost; i > 0; i-- {
		pwds = crypto.MD5HashString(pwds)
	}
	//verx := "$01$03$"
	return &GeneratePasswd{
		Password:     pwds,
		PasswordType: ptype,
		PasswordSalt: salt,
	}, nil
}
