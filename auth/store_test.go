package auth

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// storeContract : ce que toute LocalStore doit faire, joué sur SQLite et, si
// GAMEKIT_TEST_POSTGRES est donné, sur Postgres.
func storeContract(t *testing.T, s LocalStore) {
	ctx := context.Background()
	now := time.UnixMilli(1_800_000_000_000)

	alice, err := s.Signup(ctx, Account{ID: newUUID(), Username: "alice", Name: "Alice"}, "h1", "", now)
	if err != nil || !alice.Admin {
		t.Fatalf("premier compte : %+v %v", alice, err)
	}
	if _, err := s.Signup(ctx, Account{ID: newUUID(), Username: "alice", Name: "Autre"}, "h", "", now); !errors.Is(err, ErrTaken) {
		t.Fatalf("nom pris : %v", err)
	}
	if _, err := s.Signup(ctx, Account{ID: newUUID(), Username: "bob", Name: "Bob"}, "h", "inconnue", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invitation inconnue : %v", err)
	}
	if err := s.CreateTicket(ctx, Ticket{Hash: "inv", Kind: TicketInvite, CreatedBy: alice.ID, Expires: now.Add(time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	// Nom pris avec une invitation : l'invitation n'est pas consommée (transaction annulée).
	if _, err := s.Signup(ctx, Account{ID: newUUID(), Username: "alice", Name: "X"}, "h", "inv", now); !errors.Is(err, ErrTaken) {
		t.Fatalf("nom pris avec invitation : %v", err)
	}
	bob, err := s.Signup(ctx, Account{ID: newUUID(), Username: "bob", Name: "Bob"}, "h2", "inv", now)
	if err != nil || bob.Admin {
		t.Fatalf("compte invité : %+v %v", bob, err)
	}
	if _, err := s.Signup(ctx, Account{ID: newUUID(), Username: "carol", Name: "Carol"}, "h", "inv", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invitation réutilisée : %v", err)
	}
	if n, _ := s.CountAccounts(ctx); n != 2 {
		t.Fatalf("comptes : %d", n)
	}
	a, hash, err := s.AccountByUsername(ctx, "bob")
	if err != nil || hash != "h2" || a.ID != bob.ID || a.Created.UnixMilli() != now.UnixMilli() {
		t.Fatalf("par nom : %+v %q %v", a, hash, err)
	}
	if _, _, err := s.AccountByUsername(ctx, "personne"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("inconnu : %v", err)
	}
	if err := s.SetName(ctx, bob.ID, "Bob le Malin"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPassword(ctx, bob.ID, "h3"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetName(ctx, "absent", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nom d'un absent : %v", err)
	}
	all, err := s.Accounts(ctx)
	if err != nil || len(all) != 2 || all[1].Name != "Bob le Malin" {
		t.Fatalf("liste : %+v %v", all, err)
	}

	// Sessions.
	for _, tok := range []string{"s1", "s2"} {
		if err := s.CreateSession(ctx, tok, bob.ID, now.Add(time.Hour), now); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateSession(ctx, "vieille", bob.ID, now.Add(-time.Minute), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if a, err := s.SessionAccount(ctx, "s1", now); err != nil || a.ID != bob.ID {
		t.Fatalf("session : %+v %v", a, err)
	}
	if _, err := s.SessionAccount(ctx, "vieille", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session expirée : %v", err)
	}
	if err := s.DeleteSessions(ctx, bob.ID, "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionAccount(ctx, "s2", now); !errors.Is(err, ErrNotFound) {
		t.Fatal("autre session encore ouverte")
	}
	if _, err := s.SessionAccount(ctx, "s1", now); err != nil {
		t.Fatal("session gardée fermée")
	}
	if err := s.DeleteSession(ctx, "s1"); err != nil {
		t.Fatal(err)
	}

	// Liens de nouveau mot de passe.
	if err := s.CreateTicket(ctx, Ticket{Hash: "rst", Kind: TicketReset, AccountID: bob.ID, CreatedBy: alice.ID, Expires: now.Add(time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UseTicket(ctx, "rst", TicketInvite, now); !errors.Is(err, ErrNotFound) {
		t.Fatal("lien utilisé pour un autre usage")
	}
	tk, err := s.UseTicket(ctx, "rst", TicketReset, now)
	if err != nil || tk.AccountID != bob.ID || tk.CreatedBy != alice.ID {
		t.Fatalf("lien : %+v %v", tk, err)
	}
	if _, err := s.UseTicket(ctx, "rst", TicketReset, now); !errors.Is(err, ErrNotFound) {
		t.Fatal("lien réutilisé")
	}
	if err := s.CreateTicket(ctx, Ticket{Hash: "exp", Kind: TicketReset, AccountID: bob.ID, CreatedBy: alice.ID, Expires: now.Add(-time.Second)}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UseTicket(ctx, "exp", TicketReset, now); !errors.Is(err, ErrNotFound) {
		t.Fatal("lien expiré accepté")
	}
	if err := s.Purge(ctx, now); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteStore(t *testing.T) {
	db, err := sql.Open("sqlite", "file:contrat?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	s, err := NewSQLStore(context.Background(), db, SQLite)
	if err != nil {
		t.Fatal(err)
	}
	storeContract(t, s)
}

func TestPostgresStore(t *testing.T) {
	dsn := os.Getenv("GAMEKIT_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("GAMEKIT_TEST_POSTGRES absent")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, tbl := range []string{"auth_accounts", "auth_sessions", "auth_tickets"} {
		if _, err := db.Exec("DROP TABLE IF EXISTS " + tbl); err != nil && !strings.Contains(err.Error(), "does not exist") {
			t.Fatal(err)
		}
	}
	s, err := NewSQLStore(context.Background(), db, Postgres)
	if err != nil {
		t.Fatal(err)
	}
	storeContract(t, s)
}
