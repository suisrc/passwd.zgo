package passwd

import "github.com/suisrc/crypto.zgo"

// VerifySHA1 bcrypt
func VerifySHA1(ent IEntity) (bool, error) {
	epwd := crypto.MaskEncrypt([]byte(ent.Target()), []byte(ent.Salt()))
	pwds := crypto.SHA1Hash(epwd)
	for i := mCost; i > 0; i-- {
		pwds = crypto.SHA1HashString(pwds)
	}
	return ent.Source() == pwds, nil
}

// GenerateSHA1 bcrypt
func GenerateSHA1(password string, ptype string) (*GeneratePasswd, error) {
	salt := crypto.UUID(32)
	epwd := crypto.MaskEncrypt([]byte(password), []byte(salt))
	pwds := crypto.SHA1Hash(epwd)
	for i := mCost; i > 0; i-- {
		pwds = crypto.SHA1HashString(pwds)
	}
	return &GeneratePasswd{
		Password:     pwds,
		PasswordType: ptype,
		PasswordSalt: salt,
	}, nil
}
