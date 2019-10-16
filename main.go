package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"github.com/ebfe/scard"
	"github.com/sanity-io/litter"
	"github.com/segmentio/ksuid"
	"github.com/ugorji/go/codec"
)

func die(err error) {
	fmt.Println(err)
}

func waitUntilCardPresent(ctx *scard.Context, readers []string) (int, error) {
	rs := make([]scard.ReaderState, len(readers))
	for i := range rs {
		rs[i].Reader = readers[i]
		rs[i].CurrentState = scard.StateUnaware
	}

	for {
		for i := range rs {
			if rs[i].EventState&scard.StatePresent != 0 {
				return i, nil
			}
			rs[i].CurrentState = rs[i].EventState
		}
		err := ctx.GetStatusChange(rs, -1)
		if err != nil {
			return -1, err
		}
	}
}

type Options struct {
	Rk bool `codec:"rk"`
	Uv bool `codec:"uv"`
}

type PublicKeyCredentialRpEntity struct {
	Id   string `codec:"id"`
	Name string `codec:"name"`
}

type PublicKeyCredentialUserEntity struct {
	Id   []byte `codec:"id"`
	Name string `codec:"name"`
}

type PublicKeyCredentialType struct {
	Type string `codec:"type"`
	Alg  int    `codec:"alg"`
}

type AuthenticatorMakeCredential struct {
	_struct          bool                          `codec:",uint"`
	ClientDataHash   []byte                        `codec:"1"`
	Rp               PublicKeyCredentialRpEntity   `codec:"2"`
	User             PublicKeyCredentialUserEntity `codec:"3"`
	PubKeyCredParams []PublicKeyCredentialType     `codec:"4"`
	Options          Options                       `codec:"7"`
}

// type AuthenticatorData struct {

// }

type AuthenticatorMakeCredentialResponse struct {
	_struct  bool                   `codec:",uint"`
	Fmt      string                 `codec:"1"`
	AuthData []byte                 `codec:"2"`
	AttStmt  map[string]interface{} `codec:"3"`
}

var h = codec.CborHandle{}

func main() {
	userId := ksuid.New()
	makeCredReq := &AuthenticatorMakeCredential{
		ClientDataHash: []byte{104, 113, 52, 150, 130, 34, 236, 23, 32, 46, 66,
			80, 95, 142, 210, 177, 106, 226, 47, 22, 187, 5,
			184, 140, 37, 219, 158, 96, 38, 69, 241, 65},
		Rp: PublicKeyCredentialRpEntity{
			Id:   "echo.co.uk",
			Name: "echo.co.uk",
		},
		User: PublicKeyCredentialUserEntity{
			Id:   userId.Bytes(),
			Name: "alex.barlow@echo.co.uk",
		},
		PubKeyCredParams: []PublicKeyCredentialType{
			{Type: "public-key", Alg: -257}, // RS256
			{Type: "public-key", Alg: -7},   // ES256
		},
		Options: Options{
			Rk: false,
			Uv: false,
		},
	}

	// Establish a context
	ctx, err := scard.EstablishContext()
	if err != nil {
		die(err)
	}
	defer ctx.Release()

	// List available readers
	readers, err := ctx.ListReaders()
	if err != nil {
		die(err)
	}

	fmt.Printf("Found %d readers:\n", len(readers))
	for i, reader := range readers {
		fmt.Printf("[%d] %s\n", i, reader)
	}

	var card *scard.Card
	if len(readers) > 0 {
		for {
			func() {
				fmt.Println("Waiting for a Card")
				index, err := waitUntilCardPresent(ctx, readers)
				if err != nil {
					die(err)
				}

				// Connect to card
				fmt.Println("Connecting to card in ", readers[index])
				card, err = ctx.Connect(readers[index], scard.ShareExclusive, scard.ProtocolAny)
				if err != nil {
					die(err)
				}
				defer card.Disconnect(scard.ResetCard)

				fmt.Println("Card status:")
				status, err := card.Status()
				if err != nil {
					die(err)
				}

				fmt.Printf("\treader: %s\n\tstate: %x\n\tactive protocol: %x\n\tatr: % x\n",
					status.Reader, status.State, status.ActiveProtocol, status.Atr)

				time.Sleep(100 * time.Millisecond)

				var cmd = []byte{0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01}

				fmt.Println("Transmit:")
				fmt.Printf("\tc-apdu: % x\n", cmd)
				rsp, err := card.Transmit(cmd)
				if err != nil {
					die(err)
				}
				fmt.Printf("\tr-apdu: % x\n", rsp)

				makeCredRes := &AuthenticatorMakeCredentialResponse{}
				err = runCMD(card, MAKE_CREDENTIAL, makeCredReq, makeCredRes)
				if err != nil {
					log.Fatal(err)
				}
				ad, err := parseAuthenticatorData(makeCredRes.AuthData)
				if err != nil {
					log.Fatal(err)
				}

				litter.Dump(makeCredRes)
				litter.Dump(ad)

				time.Sleep(10 * time.Second)
			}()
		}
	}
}

type AuthenticatorData struct {
	RpIdHash  []byte
	Flags     []byte
	SignCount []byte
}

func parseAuthenticatorData(b []byte) (AuthenticatorData, error) {
	return AuthenticatorData{
		RpIdHash:  b[:32],
		Flags:     b[32:33],
		SignCount: b[33:37],
	}, nil
}

type Instruction int

const (
	MAKE_CREDENTIAL Instruction = iota
	GET_ASSERTION
	GET_INFO
	CLIENT_PIN
	RESET
	GET_NEXT_ASSERTION
)

var Instructions = map[Instruction]int{
	MAKE_CREDENTIAL:    0x01,
	GET_ASSERTION:      0x02,
	GET_INFO:           0x04,
	CLIENT_PIN:         0x06,
	RESET:              0x07,
	GET_NEXT_ASSERTION: 0x08,
}

var OK = []byte{0x90}
var MORE_BYTES_AVAILABLE = []byte{0x61}

func runCMD(card *scard.Card, inst Instruction, corbObjectIn, corbObjectOut interface{}) error {
	instC := make([]byte, 2)
	binary.LittleEndian.PutUint16(instC, uint16(Instructions[inst]))

	var b []byte
	enc := codec.NewEncoderBytes(&b, &h)
	err := enc.Encode(corbObjectIn)
	if err != nil {
		log.Fatal(err)
	}

	lenC := make([]byte, 2)
	binary.LittleEndian.PutUint16(lenC, uint16(len(b)))
	makeReq := []byte{0x80, 0x10, 0x80, 0x00, lenC[0]}
	makeReq = append(makeReq, instC[0])
	apdu := append(makeReq, b...)

	res, sw1, sw2, err := apduCMD(card, apdu)
	if err != nil {
		return err
	}

	for bytes.Compare(sw1, MORE_BYTES_AVAILABLE) == 0 {
		apdu = []byte{0x00, 0xC0, 0x00, 0x00, sw2}
		var r2 []byte
		r2, sw1, sw2, err = apduCMD(card, apdu)
		if err != nil {
			return err
		}

		res = append(res, r2...)
	}

	if bytes.Compare(sw1, OK) == 0 {
		if len(res) > 0 {
			dec := codec.NewDecoderBytes(res[1:], &h)
			err = dec.Decode(corbObjectOut)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func apduCMD(card *scard.Card, apdu []byte) ([]byte, []byte, byte, error) {
	rsp, err := card.Transmit(apdu)
	if err != nil {
		return nil, nil, 0x00, err
	}

	if len(rsp) > 2 {
		return rsp[:len(rsp)-3], rsp[len(rsp)-2 : len(rsp)-1], rsp[len(rsp)-1], nil
	}

	return nil, rsp[len(rsp)-2 : len(rsp)-1], rsp[len(rsp)-1], nil
}
