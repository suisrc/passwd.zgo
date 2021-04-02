module github.com/suisrc/passwd.zgo

go 1.16

replace github.com/suisrc/crypto.zgo v0.0.0 => ../crypto

require (
	github.com/stretchr/testify v1.7.0
	github.com/suisrc/crypto.zgo v0.0.0
)
