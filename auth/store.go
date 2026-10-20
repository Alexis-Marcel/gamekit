package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Comptes du mode local, gardés dans la base du jeu (tables auth_*). SQLStore
// marche avec SQLite et Postgres ; un jeu peut aussi fournir sa propre LocalStore.

// Account est un compte local.
type Account struct {
	ID       string
	Username string // en minuscules, unique
	Name     string // nom affiché
	Admin    bool
	Created  time.Time
}

// Ticket est un lien à usage unique : une invitation (inscription) ou une
// réinitialisation de mot de passe (pour AccountID).
type Ticket struct {
	Hash      string // SHA-256 du code : le code lui-même n'est jamais gardé
	Kind      string // invite, reset
	AccountID string
	CreatedBy string
	Expires   time.Time
}

const (
	TicketInvite = "invite"
	TicketReset  = "reset"
)

var (
	ErrNotFound = errors.New("introuvable")
	ErrTaken    = errors.New("ce nom d'utilisateur est déjà pris")
)

type LocalStore interface {
	// Signup crée un compte, administrateur s'il est le premier. Avec une
	// invitation (son empreinte), elle est consommée dans la même transaction :
	// ErrNotFound si elle n'est plus valable, ErrTaken si le nom est pris.
	Signup(ctx context.Context, a Account, passwordHash, inviteHash string, now time.Time) (Account, error)
	CountAccounts(ctx context.Context) (int, error)
	AccountByUsername(ctx context.Context, username string) (Account, string, error)
	Accounts(ctx context.Context) ([]Account, error)
	SetPassword(ctx context.Context, accountID, passwordHash string) error
	SetName(ctx context.Context, accountID, name string) error

	CreateSession(ctx context.Context, tokenHash, accountID string, expires, now time.Time) error
	SessionAccount(ctx context.Context, tokenHash string, now time.Time) (Account, error)
	DeleteSession(ctx context.Context, tokenHash string) error
	// DeleteSessions ferme les sessions d'un compte, sauf except (la session en cours).
	DeleteSessions(ctx context.Context, accountID, except string) error

	CreateTicket(ctx context.Context, t Ticket, now time.Time) error
	// UseTicket consomme un lien encore valable et le renvoie, sinon ErrNotFound.
	UseTicket(ctx context.Context, hash, kind string, now time.Time) (Ticket, error)
	// Purge efface les sessions et les liens expirés.
	Purge(ctx context.Context, now time.Time) error
}

// Dialect : la seule différence entre les bases, la façon d'écrire les paramètres.
type Dialect int

const (
	SQLite   Dialect = iota // ?
	Postgres                // $1, $2…
)

type SQLStore struct {
	db      *sql.DB
	dialect Dialect
}

// NewSQLStore crée les tables auth_* si besoin et renvoie le store.
func NewSQLStore(ctx context.Context, db *sql.DB, d Dialect) (*SQLStore, error) {
	s := &SQLStore{db: db, dialect: d}
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS auth_accounts (
			id            TEXT PRIMARY KEY,
			username      TEXT NOT NULL UNIQUE,
			name          TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			admin         INTEGER NOT NULL DEFAULT 0,
			created_at    BIGINT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS auth_sessions (
			token_hash TEXT PRIMARY KEY,
			account_id TEXT NOT NULL,
			expires_at BIGINT NOT NULL,
			created_at BIGINT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS auth_sessions_account ON auth_sessions (account_id)`,
		`CREATE TABLE IF NOT EXISTS auth_tickets (
			hash       TEXT PRIMARY KEY,
			kind       TEXT NOT NULL,
			account_id TEXT,
			created_by TEXT NOT NULL,
			expires_at BIGINT NOT NULL,
			used_at    BIGINT
		)`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return nil, fmt.Errorf("tables des comptes : %w", err)
		}
	}
	return s, nil
}

// q adapte les paramètres « ? » au dialecte.
func (s *SQLStore) q(query string) string {
	if s.dialect != Postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

type scanner interface{ Scan(...any) error }

func scanAccount(r scanner, extra ...any) (Account, error) {
	var a Account
	var admin int
	var created int64
	err := r.Scan(append([]any{&a.ID, &a.Username, &a.Name, &admin, &created}, extra...)...)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	a.Admin, a.Created = admin != 0, time.UnixMilli(created)
	return a, err
}

const accountCols = `a.id, a.username, a.name, a.admin, a.created_at`

func (s *SQLStore) Signup(ctx context.Context, a Account, hash, invite string, now time.Time) (Account, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return a, err
	}
	defer tx.Rollback()
	if invite != "" {
		res, err := tx.ExecContext(ctx, s.q(`UPDATE auth_tickets SET used_at = ?
			WHERE hash = ? AND kind = ? AND used_at IS NULL AND expires_at > ?`), now.UnixMilli(), invite, TicketInvite, now.UnixMilli())
		if err != nil {
			return a, err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return a, ErrNotFound
		}
	}
	var taken, count int
	if err := tx.QueryRowContext(ctx, s.q(`SELECT COUNT(*) FROM auth_accounts WHERE username = ?`), a.Username).Scan(&taken); err != nil {
		return a, err
	}
	if taken > 0 {
		return a, ErrTaken
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_accounts`).Scan(&count); err != nil {
		return a, err
	}
	a.Admin = count == 0
	a.Created = now
	admin := 0
	if a.Admin {
		admin = 1
	}
	if _, err := tx.ExecContext(ctx, s.q(`INSERT INTO auth_accounts (id, username, name, password_hash, admin, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`), a.ID, a.Username, a.Name, hash, admin, now.UnixMilli()); err != nil {
		return a, err
	}
	return a, tx.Commit()
}

func (s *SQLStore) CountAccounts(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_accounts`).Scan(&n)
	return n, err
}

func (s *SQLStore) AccountByUsername(ctx context.Context, username string) (Account, string, error) {
	var hash string
	a, err := scanAccount(s.db.QueryRowContext(ctx, s.q(`SELECT `+accountCols+`, a.password_hash
		FROM auth_accounts a WHERE a.username = ?`), username), &hash)
	return a, hash, err
}

func (s *SQLStore) Accounts(ctx context.Context) ([]Account, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+accountCols+` FROM auth_accounts a ORDER BY a.created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *SQLStore) SetPassword(ctx context.Context, id, hash string) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE auth_accounts SET password_hash = ? WHERE id = ?`), hash, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLStore) SetName(ctx context.Context, id, name string) error {
	res, err := s.db.ExecContext(ctx, s.q(`UPDATE auth_accounts SET name = ? WHERE id = ?`), name, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLStore) CreateSession(ctx context.Context, token, id string, expires, now time.Time) error {
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO auth_sessions (token_hash, account_id, expires_at, created_at) VALUES (?, ?, ?, ?)`),
		token, id, expires.UnixMilli(), now.UnixMilli())
	return err
}

func (s *SQLStore) SessionAccount(ctx context.Context, token string, now time.Time) (Account, error) {
	return scanAccount(s.db.QueryRowContext(ctx, s.q(`SELECT `+accountCols+`
		FROM auth_sessions x JOIN auth_accounts a ON a.id = x.account_id
		WHERE x.token_hash = ? AND x.expires_at > ?`), token, now.UnixMilli()))
}

func (s *SQLStore) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM auth_sessions WHERE token_hash = ?`), token)
	return err
}

func (s *SQLStore) DeleteSessions(ctx context.Context, id, except string) error {
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM auth_sessions WHERE account_id = ? AND token_hash <> ?`), id, except)
	return err
}

func (s *SQLStore) CreateTicket(ctx context.Context, t Ticket, now time.Time) error {
	var account any
	if t.AccountID != "" {
		account = t.AccountID
	}
	_, err := s.db.ExecContext(ctx, s.q(`INSERT INTO auth_tickets (hash, kind, account_id, created_by, expires_at) VALUES (?, ?, ?, ?, ?)`),
		t.Hash, t.Kind, account, t.CreatedBy, t.Expires.UnixMilli())
	return err
}

func (s *SQLStore) UseTicket(ctx context.Context, hash, kind string, now time.Time) (Ticket, error) {
	t := Ticket{Hash: hash, Kind: kind}
	var account sql.NullString
	var expires int64
	err := s.db.QueryRowContext(ctx, s.q(`UPDATE auth_tickets SET used_at = ?
		WHERE hash = ? AND kind = ? AND used_at IS NULL AND expires_at > ?
		RETURNING account_id, created_by, expires_at`), now.UnixMilli(), hash, kind, now.UnixMilli()).Scan(&account, &t.CreatedBy, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	t.AccountID, t.Expires = account.String, time.UnixMilli(expires)
	return t, err
}

func (s *SQLStore) Purge(ctx context.Context, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, s.q(`DELETE FROM auth_sessions WHERE expires_at <= ?`), now.UnixMilli()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, s.q(`DELETE FROM auth_tickets WHERE expires_at <= ? OR used_at IS NOT NULL`), now.UnixMilli())
	return err
}

// newUUID : identifiant de compte (UUID v4), comme les sub des fournisseurs OIDC.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
