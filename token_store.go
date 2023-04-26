package mq

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/jmoiron/sqlx"
)

// TokenStore Mysql token store
type TokenStore struct {
	db        *sqlx.DB
	tableName string
	logger    Logger

	gcDisabled bool
	gcInterval time.Duration
	ticker     *time.Ticker

	initTableDisabled bool
}

// TokenStoreItem data item
type TokenStoreItem struct {
	ID        int64     `db:"id"`
	CreatedAt time.Time `db:"created_at"`
	ExpiresAt time.Time `db:"expires_at"`
	Code      string    `db:"code"`
	Access    string    `db:"access"`
	Refresh   string    `db:"refresh"`
	Data      []byte    `db:"data"`
}

// NewTokenStore creates Mysql store instance
func NewTokenStore(db *sqlx.DB, options ...TokenStoreOption) (*TokenStore, error) {
	store := &TokenStore{
		db:         db,
		tableName:  "oauth2_tokens",
		logger:     log.New(os.Stderr, "[OAUTH2-PG-ERROR]", log.LstdFlags),
		gcInterval: 10 * time.Minute,
	}

	for _, o := range options {
		o(store)
	}

	var err error
	if !store.initTableDisabled {
		err = store.initTable()
	}

	if err != nil {
		return store, err
	}

	if !store.gcDisabled {
		store.ticker = time.NewTicker(store.gcInterval)
		go store.gc()
	}

	return store, err
}

// Close closes the store
func (s *TokenStore) Close() error {
	if !s.gcDisabled {
		s.ticker.Stop()
	}
	return nil
}

func (s *TokenStore) gc() {
	for range s.ticker.C {
		s.clean()
	}
}

func (s *TokenStore) initTable() error {
	q := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %[1]s (
	id         BIGSERIAL   NOT NULL,
	created_at TIMESTAMPTZ NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL,
	code       TEXT        NOT NULL,
	access     TEXT        NOT NULL,
	refresh    TEXT        NOT NULL,
	data       JSONB       NOT NULL,
	CONSTRAINT %[1]s_pkey PRIMARY KEY (id)
);
CREATE INDEX IF NOT EXISTS idx_%[1]s_expires_at ON %[1]s (expires_at);
CREATE INDEX IF NOT EXISTS idx_%[1]s_code ON %[1]s (code);
CREATE INDEX IF NOT EXISTS idx_%[1]s_access ON %[1]s (access);
CREATE INDEX IF NOT EXISTS idx_%[1]s_refresh ON %[1]s (refresh);
`, s.tableName)
	_, err := s.db.Exec(q)
	return err
}

func (s *TokenStore) clean() {
	now := time.Now()
	q := fmt.Sprintf("DELETE FROM %s WHERE expires_at <= ?", s.tableName)
	_, err := s.db.Exec(q, now)
	if err != nil {
		s.logger.Printf("Error while cleaning out outdated entities: %+v", err)
	}
}

// Create creates and stores the new token information
func (s *TokenStore) Create(info oauth2.TokenInfo) error {
	buf, err := json.Marshal(info)
	if err != nil {
		return err
	}

	item := &TokenStoreItem{
		Data:      buf,
		CreatedAt: time.Now(),
	}

	if code := info.GetCode(); code != "" {
		item.Code = code
		item.ExpiresAt = info.GetCodeCreateAt().Add(info.GetCodeExpiresIn())
	} else {
		item.Access = info.GetAccess()
		item.ExpiresAt = info.GetAccessCreateAt().Add(info.GetAccessExpiresIn())

		if refresh := info.GetRefresh(); refresh != "" {
			item.Refresh = info.GetRefresh()
			item.ExpiresAt = info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn())
		}
	}
	q := fmt.Sprintf("INSERT INTO %s (created_at, expires_at, code, access, refresh, data) VALUES (?, ?, ?, ?, ?, ?)", s.tableName)
	_, err = s.db.Exec(q,
		item.CreatedAt,
		item.ExpiresAt,
		item.Code,
		item.Access,
		item.Refresh,
		item.Data,
	)
	return err
}

// RemoveByCode deletes the authorization code
func (s *TokenStore) RemoveByCode(code string) error {
	_, err := s.db.Exec(fmt.Sprintf("DELETE FROM %s WHERE code = ?", s.tableName), code)
	if err == sql.ErrNoRows {
		return nil
	}
	return err
}

// RemoveByAccess uses the access token to delete the token information
func (s *TokenStore) RemoveByAccess(access string) error {
	_, err := s.db.Exec(fmt.Sprintf("DELETE FROM %s WHERE access = ?", s.tableName), access)
	if err == sql.ErrNoRows {
		return nil
	}
	return err
}

// RemoveByRefresh uses the refresh token to delete the token information
func (s *TokenStore) RemoveByRefresh(refresh string) error {
	_, err := s.db.Exec(fmt.Sprintf("DELETE FROM %s WHERE refresh = ?", s.tableName), refresh)
	if err == sql.ErrNoRows {
		return nil
	}
	return err
}

func (s *TokenStore) toTokenInfo(data []byte) (oauth2.TokenInfo, error) {
	var tm models.Token
	err := json.Unmarshal(data, &tm)
	return &tm, err
}

// GetByCode uses the authorization code for token information data
func (s *TokenStore) GetByCode(code string) (oauth2.TokenInfo, error) {
	if code == "" {
		return nil, nil
	}

	var item TokenStoreItem
	if err := s.db.Get(&item, fmt.Sprintf("SELECT * FROM %s WHERE code = ?", s.tableName), code); err != nil {
		return nil, err
	}

	return s.toTokenInfo(item.Data)
}

// GetByAccess uses the access token for token information data
func (s *TokenStore) GetByAccess(access string) (oauth2.TokenInfo, error) {
	if access == "" {
		return nil, nil
	}

	var item TokenStoreItem
	if err := s.db.Get(&item, fmt.Sprintf("SELECT * FROM %s WHERE access = ?", s.tableName), access); err != nil {
		return nil, err
	}

	return s.toTokenInfo(item.Data)
}

// GetByRefresh uses the refresh token for token information data
func (s *TokenStore) GetByRefresh(refresh string) (oauth2.TokenInfo, error) {
	if refresh == "" {
		return nil, nil
	}

	var item TokenStoreItem
	if err := s.db.Get(&item, fmt.Sprintf("SELECT * FROM %s WHERE refresh = ?", s.tableName), refresh); err != nil {
		return nil, err
	}

	return s.toTokenInfo(item.Data)
}
