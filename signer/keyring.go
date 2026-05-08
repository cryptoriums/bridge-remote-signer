package signer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	cosmossecp "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"golang.org/x/term"
)

const secp256k1KeyLen = 32

const unlockPage = `<!doctype html><html><head><meta charset="utf-8"><title>Unlock</title></head><body><form method="POST"><label>Password: <input name="pass" type="password" required></label><button type="submit">Unlock</button></form>{{MSG}}</body></html>`

// MakeKeyringCodec builds a codec that registers the standard cosmos-sdk
// crypto interfaces. The keyring needs this to unmarshal the Any wrapped
// private and public keys it stores.
func MakeKeyringCodec() codec.Codec {
	registry := codectypes.NewInterfaceRegistry()
	cryptocodec.RegisterInterfaces(registry)
	return codec.NewProtoCodec(registry)
}

func BuildPasswordReader(passwordFile, webPort, keyringDir, keyName string) (io.Reader, error) {
	if strings.EqualFold(os.Getenv("KEYRING_UNLOCK_MODE"), "web") {
		pass, err := webUnlock(webPort, keyringDir, keyName)
		if err != nil {
			return nil, err
		}
		return strings.NewReader(pass + "\n"), nil
	}

	if passwordFile != "" {
		return buildFilePasswordReader(passwordFile)
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("stdin is not a terminal; set the password file option or KEYRING_UNLOCK_MODE=web")
	}
	return os.Stdin, nil
}

func webUnlock(port, keyringDir, keyName string) (string, error) {
	if port == "" {
		port = "8888"
	}
	cdc := MakeKeyringCodec()
	passCh := make(chan string, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writePage(w, http.StatusOK, "")
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		pass := strings.TrimSpace(r.FormValue("pass"))
		if pass == "" {
			writePage(w, http.StatusBadRequest, "Password is required")
			return
		}
		if err := validateKeyringPass(pass, keyringDir, keyName, cdc); err != nil {
			writePage(w, http.StatusUnauthorized, "Incorrect password")
			return
		}
		_, _ = w.Write([]byte("unlocked"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case passCh <- pass:
		default:
		}
	})
	server := &http.Server{Addr: ":" + port, Handler: mux}
	go server.ListenAndServe()
	return <-passCh, nil
}

func validateKeyringPass(pass, keyringDir, keyName string, cdc codec.Codec) error {
	kr, err := keyring.New(sdk.KeyringServiceName(), keyring.BackendFile, keyringDir, strings.NewReader(pass+"\n"), cdc)
	if err != nil {
		return err
	}
	_, _, err = kr.Sign(keyName, []byte("unlock validation"), 1)
	return err
}

func writePage(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html;  charset=utf8")
	w.WriteHeader(status)
	replace := ""
	if msg != "" {
		replace = "<p style=\"color:red;\">" + msg + "</p>"
	}
	_, _ = io.WriteString(w, strings.Replace(unlockPage, "{{MSG}}", replace, 1))
}

func buildFilePasswordReader(path string) (io.Reader, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat password file %q: %w", path, err)
	}

	// Only 0600 mode is allowed.
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf(
			"password file %q has permissions %04o; expected 0600",
			path, perm,
		)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read password file %q: %w", path, err)
	}

	password := bytes.TrimRight(data, "\r\n")
	if len(password) == 0 {
		return nil, fmt.Errorf("password file %q is empty", path)
	}

	line := append(bytes.Clone(password), '\n')
	return &repeatingReader{line: line}, nil
}

type repeatingReader struct {
	line []byte
	off  int
}

func (r *repeatingReader) Read(p []byte) (int, error) {
	if r.off >= len(r.line) {
		r.off = 0
	}
	n := copy(p, r.line[r.off:])
	r.off += n
	return n, nil
}

func ExtractSecpPrivKeyBytes(cdc codec.Codec, record *keyring.Record) ([]byte, error) {
	if record == nil {
		return nil, errors.New("nil keyring record")
	}

	localItem := record.GetLocal()
	if localItem == nil {
		return nil, fmt.Errorf("key %q is not a local key (ledger and multisig keys not supported)", record.Name)
	}

	var privKey cryptotypes.PrivKey
	if err := cdc.UnpackAny(localItem.PrivKey, &privKey); err != nil {
		return nil, fmt.Errorf("unpack private key for %q: %w", record.Name, err)
	}

	secp, ok := privKey.(*cosmossecp.PrivKey)
	if !ok {
		return nil, fmt.Errorf("key %q is %T, want *secp256k1.PrivKey", record.Name, privKey)
	}
	if len(secp.Key) != secp256k1KeyLen {
		return nil, fmt.Errorf("key %q has length %d, want %d", record.Name, len(secp.Key), secp256k1KeyLen)
	}

	out := make([]byte, secp256k1KeyLen)
	copy(out, secp.Key)
	return out, nil
}
