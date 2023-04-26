package mq

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/jmoiron/sqlx"
)

// ClientStore Mysql client store
type ClientStore struct {
	db                *sqlx.DB
	tableName         string
	logger            Logger
	initTableDisabled bool
}

// ClientStoreItem data item
type ClientStoreItem struct {
	ID     string `db:"id"`
	Secret string `db:"secret"`
	Domain string `db:"domain"`
	Data   []byte `db:"data"`
}

// NewClientStore creates Mariadb store instance
func NewClientStore(db *sqlx.DB, options ...ClientStoreOption) (*ClientStore, error) {
	store := &ClientStore{
		db:        db,
		tableName: "oauth2_clients",
		logger:    log.New(os.Stderr, "[OAUTH2-MYSQL-ERROR]", log.LstdFlags),
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

	return store, err
}

func (s *ClientStore) initTable() error {
	_, err := s.db.Exec(fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %[1]s (
	id     Varchar(255)  NOT NULL Primary Key,
	secret Varchar(255)  NOT NULL,
	domain Varchar(255)  NOT NULL,
	data   Text NOT NULL);
`, s.tableName))
	return err
}

func (s *ClientStore) toClientInfo(data []byte) (oauth2.ClientInfo, error) {
	var cm models.Client
	err := json.Unmarshal(data, &cm)
	return &cm, err
}

// GetByID retrieves and returns client information by id
func (s *ClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	if id == "" {
		return nil, nil
	}

	var item ClientStoreItem
	q := fmt.Sprintf("SELECT * FROM %s WHERE id = ?", s.tableName)
	if err := s.db.Get(&item, q, id); err != nil {
		return nil, err
	}
	return s.toClientInfo(item.Data)
}

// Create creates and stores the n	ew client information
func (s *ClientStore) Create(info oauth2.ClientInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	q := fmt.Sprintf("INSERT INTO %s (id, secret, domain, data) VALUES (?, ?, ?, ?)", s.tableName)
	_, err = s.db.Exec(
		q,
		info.GetID(),
		info.GetSecret(),
		info.GetDomain(),
		string(data),
	)
	return err
}
