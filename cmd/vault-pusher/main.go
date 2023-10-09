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

	if err := run(ctx); err != nil {
		panic(err)
	}
}

func run(ctx context.Context) error {
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
	authInfo, err := client.Auth().Login(ctx, appRoleAuth)
	if err != nil {
		return fmt.Errorf("failed to log in using the approle method: %w", err)
	}
	if authInfo == nil {
		return errors.New("auth method did not return valid credentials")
	}

	if err := manageTokenLifecycle(client, authInfo); err != nil {
		return fmt.Errorf("unable to start managing token lifecycle: %w", err)
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

// Reference: https://github.com/hashicorp/vault-examples/blob/main/examples/token-renewal/go/example.go

// Starts token lifecycle management. Returns only fatal errors as errors,
// otherwise returns nil so we can attempt login again.
func manageTokenLifecycle(client *vault.Client, token *vault.Secret) error {
	renew := token.Auth.Renewable // You may notice a different top-level field called Renewable. That one is used for dynamic secrets renewal, not token renewal.
	if !renew {
		log.Printf("Token is not configured to be renewable. Re-attempting login.")
		return nil
	}

	watcher, err := client.NewLifetimeWatcher(&vault.LifetimeWatcherInput{
		Secret:    token,
		Increment: 60 * 60 * 24, // Learn more about this optional value in https://www.vaultproject.io/docs/concepts/lease#lease-durations-and-renewal
	})
	if err != nil {
		return fmt.Errorf("unable to initialize new lifetime watcher for renewing auth token: %w", err)
	}

	go watcher.Start()
	defer watcher.Stop()

	for {
		select {
		// `DoneCh` will return if renewal fails, or if the remaining lease
		// duration is under a built-in threshold and either renewing is not
		// extending it or renewing is disabled. In any case, the caller
		// needs to attempt to log in again.
		case err := <-watcher.DoneCh():
			if err != nil {
				log.Printf("Failed to renew token: %v. Re-attempting login.", err)
				return nil
			}
			// This occurs once the token has reached max TTL.
			log.Printf("Token can no longer be renewed. Re-attempting login.")
			return nil

		// Successfully completed renewal
		case renewal := <-watcher.RenewCh():
			log.Printf("Successfully renewed: %#v", renewal)
		}
	}
}
