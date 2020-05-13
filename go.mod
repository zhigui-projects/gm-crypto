module github.com/zhigui-projects/gm-crypto

go 1.12

require (
	github.com/golang/protobuf v1.4.1
	github.com/zhigui-projects/gm-plugins v0.0.0
	golang.org/x/crypto v0.0.0-20200427165652-729f1e841bcc
	golang.org/x/lint v0.0.0-20190313153728-d0100b6bd8b3 // indirect
	golang.org/x/net v0.0.0-20191209160850-c0dbc17a3553
	golang.org/x/tools v0.0.0-20190524140312-2c0ae7006135 // indirect
	google.golang.org/grpc v1.29.1
	honnef.co/go/tools v0.0.0-20190523083050-ea95bdfd59fc // indirect
)

replace github.com/zhigui-projects/gm-go => gitlab.ziggurat.cn/guomi/gm-go v0.0.0-20200510034956-8e4ef670d055

replace github.com/zhigui-projects/gm-plugins => gitlab.ziggurat.cn/guomi/gm-plugins v0.0.0-20200510040627-61f212b0eb18
