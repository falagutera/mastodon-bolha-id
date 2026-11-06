// id is a small OpenID Connect provider for one Mastodon instance. People sign
// in with their instance account; only approved, active accounts get through.
// See README.md.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed assets
var assetFS embed.FS

const drainTimeout = 20 * time.Second

type config struct {
	listen               string
	issuer               string
	instance             string
	domain               string
	lang                 string
	mastodonClientID     string
	mastodonClientSecret string
	adminToken           string
	signingKey           string
	previousKey          string
	clientsFile          string
	allowSilenced        bool
	roleGroups           map[string]string // Mastodon role id -> group name
	sessionTTL           time.Duration
	refreshTTL           time.Duration
	dbHost               string
	dbPort               string
	dbUser               string
	dbPassword           string
	dbName               string
	dbSSLMode            string
	redisAddr            string
	redisPassword        string
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// secretEnv reads KEY, or the file named by KEY_FILE.
func secretEnv(key string) (string, error) {
	if v := os.Getenv(key); v != "" {
		return v, nil
	}
	if path := os.Getenv(key + "_FILE"); path != "" {
		b, err := os.ReadFile(path) // #nosec G304 G703 -- path set by the operator (env), not by requests
		if err != nil {
			return "", fmt.Errorf("%s_FILE: %w", key, err)
		}
		return string(b), nil
	}
	return "", nil
}

func boolEnv(key string, fallback bool) (bool, error) {
	switch strings.ToLower(os.Getenv(key)) {
	case "":
		return fallback, nil
	case "true", "1", "yes":
		return true, nil
	case "false", "0", "no":
		return false, nil
	}
	return false, fmt.Errorf("%s must be true or false", key)
}

func durationEnv(key string, fallback, min, max time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < min || d > max {
		return 0, fmt.Errorf("%s must be a duration between %s and %s", key, min, max)
	}
	return d, nil
}

func loadConfig() (config, error) {
	c := config{
		listen:               env("ID_LISTEN", ":8080"),
		issuer:               strings.TrimRight(os.Getenv("ID_ISSUER"), "/"),
		instance:             strings.TrimRight(os.Getenv("ID_INSTANCE"), "/"),
		lang:                 env("ID_LANG", "pt-BR"),
		mastodonClientID:     os.Getenv("ID_MASTODON_CLIENT_ID"),
		mastodonClientSecret: os.Getenv("ID_MASTODON_CLIENT_SECRET"),
		adminToken:           os.Getenv("ID_MASTODON_ADMIN_TOKEN"),
		clientsFile:          os.Getenv("ID_CLIENTS_FILE"),
		dbHost:               os.Getenv("ID_DB_HOST"),
		dbPort:               env("ID_DB_PORT", "5432"),
		dbUser:               env("ID_DB_USER", "id"),
		dbPassword:           os.Getenv("ID_DB_PASSWORD"),
		dbName:               env("ID_DB_NAME", "id"),
		dbSSLMode:            env("ID_DB_SSLMODE", "require"),
		redisAddr:            os.Getenv("ID_REDIS_ADDR"),
		redisPassword:        os.Getenv("ID_REDIS_PASSWORD"),
	}
	var err error
	if c.signingKey, err = secretEnv("ID_SIGNING_KEY"); err != nil {
		return c, err
	}
	if c.previousKey, err = secretEnv("ID_SIGNING_KEY_PREVIOUS"); err != nil {
		return c, err
	}
	if c.allowSilenced, err = boolEnv("ID_ALLOW_SILENCED", true); err != nil {
		return c, err
	}
	if c.sessionTTL, err = durationEnv("ID_SESSION_TTL", 2*time.Hour, 5*time.Minute, 7*24*time.Hour); err != nil {
		return c, err
	}
	if c.refreshTTL, err = durationEnv("ID_REFRESH_TTL", 30*24*time.Hour, time.Hour, 90*24*time.Hour); err != nil {
		return c, err
	}
	if c.roleGroups, err = parseRoleGroups(os.Getenv("ID_ROLE_GROUPS")); err != nil {
		return c, err
	}
	if u, err := url.Parse(c.instance); err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" {
		return c, fmt.Errorf("ID_INSTANCE must be a URL like https://example.social")
	} else {
		c.domain = u.Host
	}
	if u, err := url.Parse(c.issuer); err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return c, fmt.Errorf("ID_ISSUER must be an https URL like https://id.example.social")
	}
	switch {
	case c.mastodonClientID == "" || c.mastodonClientSecret == "":
		return c, fmt.Errorf("ID_MASTODON_CLIENT_ID and ID_MASTODON_CLIENT_SECRET are required")
	case c.adminToken == "":
		return c, fmt.Errorf("ID_MASTODON_ADMIN_TOKEN is required")
	case c.signingKey == "":
		return c, fmt.Errorf("ID_SIGNING_KEY (or ID_SIGNING_KEY_FILE) is required")
	case c.clientsFile == "":
		return c, fmt.Errorf("ID_CLIENTS_FILE is required")
	case c.dbHost == "" || c.dbPassword == "":
		return c, fmt.Errorf("ID_DB_HOST and ID_DB_PASSWORD are required")
	case c.redisAddr == "" || c.redisPassword == "":
		return c, fmt.Errorf("ID_REDIS_ADDR and ID_REDIS_PASSWORD are required")
	}
	return c, nil
}

var groupName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// parseRoleGroups reads ID_ROLE_GROUPS, a JSON object from Mastodon role id to
// the group name tools receive, such as {"3":"admin","2":"moderator"}.
func parseRoleGroups(raw string) (map[string]string, error) {
	out := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return out, nil
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("ID_ROLE_GROUPS must be a JSON object like {\"3\":\"admin\"}: %w", err)
	}
	for id, g := range out {
		if id == "" || !groupName.MatchString(g) {
			return nil, fmt.Errorf("ID_ROLE_GROUPS: bad entry %q: %q", id, g)
		}
	}
	return out, nil
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe the local server and exit")
	flag.Parse()
	if *healthcheck {
		resp, err := http.Get("http://127.0.0.1" + env("ID_LISTEN", ":8080") + "/healthz")
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		return
	}
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	keys, err := newKeySet(cfg.signingKey, cfg.previousKey)
	if err != nil {
		log.Fatal(err)
	}
	clients, err := loadClients(cfg.clientsFile)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	db, err := openStore(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := db.check(ctx); err != nil {
		log.Fatalf("database: %v (was schema.sql applied?)", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: cfg.redisAddr, Password: cfg.redisPassword})
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("redis: %v", err)
	}
	tmpl, err := parseTemplates()
	if err != nil {
		log.Fatal(err)
	}
	api := &mastodon{
		base: cfg.instance, clientID: cfg.mastodonClientID, clientSecret: cfg.mastodonClientSecret,
		redirect: cfg.issuer + "/callback", adminToken: cfg.adminToken,
		client: &http.Client{Timeout: 15 * time.Second},
	}
	s := newServer(cfg, tmpl, api, db, rdb, keys, clients)
	log.Printf("id %s listening on %s, issuer %s, instance %s, %d clients", version, cfg.listen, cfg.issuer, cfg.domain, len(clients))
	srv := &http.Server{
		Addr:              cfg.listen,
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	stop, cancel := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-stop.Done()
		done, cancel := context.WithTimeout(ctx, drainTimeout)
		defer cancel()
		if err := srv.Shutdown(done); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	<-drained
}

func parseTemplates() (*template.Template, error) {
	return template.New("").ParseFS(templateFS, "templates/*.html")
}
