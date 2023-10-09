package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/golang-jwt/jwt/v4"
	"github.com/namsral/flag"
	"github.com/pyr-sh/tbot-vault-bridge/common"
)

var (
	pusherURL      = flag.String("pusher_url", "", "url of the pusher server to use")
	jwtSecret      = flag.String("jwt_secret", "", "secret to use to auth outgoing requests")
	tbotTargetPath = flag.String("tbot_target_path", "", "path to the tbot target dir")
	keyPrefix      = flag.String("key_prefix", "tbot-", "key prefix to use")
	debounceTime   = flag.Duration("debounce_time", time.Second, "debounce time")
)

func main() {
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// create a new watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to initialize fsnotify: %w", err)
	}
	defer watcher.Close()

	// start listening to changes in the specific directory
	if err := watcher.Add(*tbotTargetPath); err != nil {
		return fmt.Errorf("failed to add the target dir to the watcher: %w", err)
	}

	// wrap up by listening to signals
	stop := make(chan os.Signal, 8)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// watch and push changes
	timer := time.NewTimer(*debounceTime) // first run happens after *debounceTime
	for {
		select {
		case <-stop:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			log.Printf("fsnotify error: %v", err)
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			log.Printf("Received a fsnotify event: %#v", event)
			if !event.Has(fsnotify.Write) {
				continue
			}
			timer.Reset(*debounceTime)
		case <-timer.C:
			if err := pushBundle(ctx, client); err != nil {
				return fmt.Errorf("failed to perform an update bundle push: %w", err)
			}
		}
	}
}

func pushBundle(ctx context.Context, client *http.Client) error {
	log.Println("Starting a synchronization iteration")

	files, err := os.ReadDir(*tbotTargetPath)
	if err != nil {
		return fmt.Errorf("failed to readdir %v: %w", *tbotTargetPath, err)
	}

	token, err := generateToken()
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}

	for _, file := range files {
		// validate and read the file
		if file.IsDir() {
			log.Printf("Skipping directory %s", file.Name())
		}
		fullPath := filepath.Join(*tbotTargetPath, file.Name())
		fileContents, err := os.ReadFile(fullPath)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", fullPath, err)
		}

		// persist it to vault
		fileName := file.Name()
		if fileName == ".write-test" {
			fileName = "." + *keyPrefix + "write-test"
		} else {
			fileName = *keyPrefix + fileName
		}
		if err := pushValue(ctx, client, token, fileName, string(fileContents)); err != nil {
			return fmt.Errorf("failed to push file %s as key %s: %w", fullPath, fileName, err)
		}
	}
	log.Println("Synchronization iteration completed")

	return nil
}

func generateToken() (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    "tbot-monitor",
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(*jwtSecret))
}

func pushValue(ctx context.Context, client *http.Client, token string, key string, value string) error {
	body, err := json.Marshal(common.KeyValue{
		Key:   key,
		Value: value,
	})
	if err != nil {
		return fmt.Errorf("failed to encode the payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, *pusherURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to initialize the new http request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute the http request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %v - body: %s", resp.StatusCode, string(body))
	}

	return nil
}
