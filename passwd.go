package passwd

import (
	"errors"
)

const (
	bCost = 9
	mCost = 3
)

// Validator 密码验证器
type Validator struct {
}

// IEntity 需要验证的实体
type IEntity interface {
	Target() string // 前端输入,待匹配的密码, 一般为原文
	Source() string // 后端存储,加密后的密码, 一般为hash值
	Salt() string   // 密码盐值, 用于胡乱密码的加密
	Type() string   // 加密类型
}

// Verify 验证密码是否通过
func (a *Validator) Verify(ent IEntity) (bool, error) {
	if ent == nil || ent.Target() == "" || ent.Source() == "" {
		return false, nil
	}
	if ent.Type() == "" {
		return ent.Target() == ent.Source(), nil
	}
	if ent.Type() == "BCR" {
		return VerifyBcrypt(ent)
	}
	if ent.Type() == "MD5" {
		return VerifyMD5(ent)
	}
	if ent.Type() == "SHA1" {
		return VerifySHA1(ent)
	}
	if ent.Type() == "BCR2" {
		return VerifyBcrypt2(ent)
	}
	if ent.Type() == "BCR3" {
		return VerifyBcrypt3(ent)
	}
	return false, nil
}

// GeneratePasswd 生成的密码
type GeneratePasswd struct {
	Password     string // 加密后的密码
	PasswordSalt string // 密码盐值
	PasswordType string // 加密类型
}

// Generate 生成密码
func (a *Validator) Generate(password string, ptype string) (*GeneratePasswd, error) {
	if ptype == "" {
		return &GeneratePasswd{
			Password: password,
		}, nil
	}
	if ptype == "BCR" {
		return GenerateBcrypt(password, ptype)
	}
	if ptype == "MD5" {
		return GenerateMD5(password, ptype)
	}
	if ptype == "SHA1" {
		return GenerateSHA1(password, ptype)
	}
	if ptype == "BCR2" {
		return GenerateBcrypt2(password, ptype)
	}
	if ptype == "BCR3" {
		return GenerateBcrypt3(password, ptype)
	}
	return nil, errors.New("unknow password type")
}

// Source right
func (a *GeneratePasswd) Source() string {
	return a.Password
}

// Salt salt
func (a *GeneratePasswd) Salt() string {
	return a.PasswordSalt
}

// Type type
func (a *GeneratePasswd) Type() string {
	return a.PasswordType
}
