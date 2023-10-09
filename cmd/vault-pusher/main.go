package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
	"github.com/namsral/flag"
)

var (
	bindAddr = flag.String("bind_addr", ":5000", "bind address")
	// the following are configured by vault itself:
	// vault_addr
	// vault_client_cert
	// vault_client_key
	vaultRoleID     = flag.String("vault_role_id", "", "vault role id")
	vaultSecretID   = flag.String("vault_secret_id", "", "vault secret id")
	vaultTargetKV   = flag.String("vault_target_kv", "", "name of the target vault kv store")
	vaultTargetPath = flag.String("vault_target_path", "", "target path under which keys will be created")
	jwtSecret       = flag.String("jwt_secret", "", "secret to use to auth incoming requests")
)

func main() {
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tokenRenewalDoneCh := make(chan struct{})
	err := run(ctx, tokenRenewalDoneCh)
	log.Println("Stopping token renewal goroutine...")
	<-tokenRenewalDoneCh
	if err != nil {
		panic(err)
	}
	log.Println("Exiting")
}

func run(ctx context.Context, tokenRenewalDoneCh chan struct{}) error {
	// connect to vault
	config := vault.DefaultConfig()
	transport := config.HttpClient.Transport.(*http.Transport)
	transport.TLSClientConfig.ClientAuth = tls.RequestClientCert
	config.HttpClient = &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport, // explicitly verbose to make patching in logger middlewares easier
	}
	client, err := vault.NewClient(config)
	if err != nil {
		return fmt.Errorf("unable to initialize vault client: %w", err)
	}
	appRoleAuth, err := auth.NewAppRoleAuth(
		*vaultRoleID,
		&auth.SecretID{
			FromString: *vaultSecretID,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to initialize approle auth method: %w", err)
	}

	// perform vault auth
	authInfo, err := login(ctx, client, appRoleAuth)
	if err != nil {
		return err
	}

	// And start token renewal lifecycle
	// Reference: https://github.com/hashicorp/vault-examples/blob/main/examples/token-renewal/go/example.go
	if authInfo.Auth.Renewable {
		go func() {
			defer func() { tokenRenewalDoneCh <- struct{}{} }()
			log.Println("Starting auto renewal goroutine")
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if authInfo == nil {
					log.Println("Reattempting login")
					authInfo, err = login(ctx, client, appRoleAuth)
					if err != nil {
						log.Printf("Failed to reattempt login: %v", err)
						continue
					}
				}

				watcher, err := client.NewLifetimeWatcher(&vault.LifetimeWatcherInput{
					Secret:    authInfo,
					Increment: 60 * 60 * 24,
				})
				if err != nil {
					log.Printf("unable to initialize new lifetime watcher for renewing auth token: %v", err)
					continue
				}

				go watcher.Start()
				defer watcher.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case err := <-watcher.DoneCh():
						if err != nil {
							log.Printf("Failed to renew token: %v", err)
						} else {
							log.Printf("Token can no longer be renewed")
						}
						authInfo = nil
						watcher.Stop()
						break
					case renewal := <-watcher.RenewCh():
						log.Printf("Successfully renewed: %#v", renewal)
					}
				}
			}
		}()
	} else {
		tokenRenewalDoneCh <- struct{}{}
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pyr-sh/tbot-vault-bridge"))
	})

	mux.HandleFunc("/push", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "invalid method", http.StatusMethodNotAllowed)
			return
		}

		// validate auth
		authz := r.Header.Get("Authorization")
		if authz == "" {
			http.Error(w, "authorization header missing", http.StatusUnauthorized)
			return
		}
		authzParts := strings.SplitN(authz, " ", 2)
		if authzParts[0] != "Bearer" || len(authzParts) < 2 {
			http.Error(w, "invalid authorization header format", http.StatusUnauthorized)
			return
		}
		token, err := jwt.Parse(authzParts[1], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(*jwtSecret), nil
		})
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to parse token: %v", err), http.StatusUnauthorized)
			return
		}

		// if the jwt is valid and using the shared secret key, it's good enough for us
		_, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// decode the input
		var input struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, fmt.Sprintf("failed to decode input: %v", err), http.StatusBadRequest)
			return
		}

		if _, err := client.KVv2(*vaultTargetKV).Put(
			ctx,
			path.Join(*vaultTargetPath, input.Key),
			map[string]interface{}{
				"value": input.Value,
			},
		); err != nil {
			http.Error(w, fmt.Sprintf("failed to push the key: %v", err), http.StatusBadRequest)
			return
		}

		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": true,
		}); err != nil {
			log.Printf("Failed to write a response: %v", err)
			return
		}
	})

	server := &http.Server{
		Addr:        *bindAddr,
		Handler:     mux,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}

	log.Printf("Listening on %s", *bindAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to listen and serve: %w", err)
	}
	log.Println("Shutting down...")
	return nil
}

func login(ctx context.Context, client *vault.Client, appRoleAuth *auth.AppRoleAuth) (*vault.Secret, error) {
	authInfo, err := client.Auth().Login(ctx, appRoleAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to log in using the approle method: %w", err)
	}
	if authInfo == nil {
		return nil, errors.New("auth method did not return valid credentials")
	}
	return authInfo, nil
}
