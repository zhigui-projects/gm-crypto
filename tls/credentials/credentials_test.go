/*
Copyright Zhigui.com. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package credentials

import (
	s "crypto/tls"
	x "crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"testing"

	gcs "github.com/zhigui-projects/gm-crypto/tls"
	"github.com/zhigui-projects/gm-crypto/tls/credentials/echo"
	gcx "github.com/zhigui-projects/gm-crypto/x509"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	port    = ":50051"
	address = "localhost:50051"
)

func init() {
	gcx.InitX509(gcx.SM2)
}

var end chan bool

type server struct{}

func (s *server) Echo(ctx context.Context, req *echo.EchoRequest) (*echo.EchoResponse, error) {
	return &echo.EchoResponse{Result: req.Req}, nil
}

const ca = "testdata/caV2.pem"
const cakey = "testdata/caKeyV2.pem"

const admin = "testdata/adminV2.pem"
const adminkey = "testdata/adminKeyV2.pem"

func serverRun() {
	cert, err := gcs.LoadX509KeyPair(ca, cakey)
	if err != nil {
		log.Fatal(err)
	}
	cp := x.NewCertPool()
	cacert, err := ioutil.ReadFile(ca)
	if err != nil {
		log.Fatal(err)
	}
	certPool := gcx.CopyFrom(cp)
	certPool.AppendCertsFromPEM(cacert)

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("fail to listen: %v", err)
	}
	creds := NewTLS(&gcs.Config{
		ClientAuth:   gcs.RequireAndVerifyClientCert,
		Certificates: []s.Certificate{cert},
		ClientCAs:    cp,
	})
	s := grpc.NewServer(grpc.Creds(creds))
	echo.RegisterEchoServer(s, &server{})
	err = s.Serve(lis)
	if err != nil {
		log.Fatalf("Serve: %v", err)
	}
}

func clientRun() {
	cert, err := gcs.LoadX509KeyPair(admin, adminkey)
	if err != nil {
		log.Fatal(err)
	}
	cp := x.NewCertPool()
	cacert, err := ioutil.ReadFile(ca)
	if err != nil {
		log.Fatal(err)
	}
	certPool := gcx.CopyFrom(cp)
	certPool.AppendCertsFromPEM(cacert)
	creds := NewTLS(&gcs.Config{
		ServerName:   "tlsca.org1.example.com",
		Certificates: []s.Certificate{cert},
		RootCAs:      cp,
	})
	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("cannot to connect: %v", err)
	}
	defer conn.Close()
	c := echo.NewEchoClient(conn)
	echoTest(c)
	end <- true
}

func echoTest(c echo.EchoClient) {
	r, err := c.Echo(context.Background(), &echo.EchoRequest{Req: "hello"})
	if err != nil {
		log.Fatalf("failed to echo: %v", err)
	}
	fmt.Printf("%s\n", r.Result)
}

func Test(t *testing.T) {
	end = make(chan bool, 64)
	go serverRun()
	go clientRun()
	<-end
}
