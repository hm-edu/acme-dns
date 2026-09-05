package database

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/hm-edu/acme-dns/pkg/acmedns"
)

func TestCountDomains(t *testing.T) {
	before, err := DB.CountDomains()
	if err != nil {
		t.Fatalf("CountDomains failed: [%v]", err)
	}
	if _, err := DB.Register(acmedns.CIDRSlice{}); err != nil {
		t.Fatalf("Registration failed, got error [%v]", err)
	}
	after, err := DB.CountDomains()
	if err != nil {
		t.Fatalf("CountDomains failed: [%v]", err)
	}
	if after != before+1 {
		t.Errorf("Expected count to grow from %d to %d, got %d", before, before+1, after)
	}
}

func TestGetDomain(t *testing.T) {
	reg, err := DB.Register(acmedns.CIDRSlice{"192.168.1.0/24", "invalid", "[::1]/128"})
	if err != nil {
		t.Fatalf("Registration failed, got error [%v]", err)
	}

	info, err := DB.GetDomain(reg.Subdomain)
	if err != nil {
		t.Fatalf("GetDomain failed: [%v]", err)
	}
	if info.Username != reg.Username {
		t.Errorf("Expected username %s, got %s", reg.Username, info.Username)
	}
	if info.Subdomain != reg.Subdomain {
		t.Errorf("Expected subdomain %s, got %s", reg.Subdomain, info.Subdomain)
	}
	if len(info.AllowFrom) != 2 {
		t.Errorf("Expected 2 allowfrom entries, got %v", info.AllowFrom)
	}
	if len(info.TXT) != 2 {
		t.Fatalf("Expected 2 TXT records for a fresh registration, got %d", len(info.TXT))
	}
	if info.HasTXT() {
		t.Errorf("Fresh registration should not have TXT values")
	}
	if info.LastUpdate() != 0 {
		t.Errorf("Fresh registration should never have been updated, got %d", info.LastUpdate())
	}

	validTXT := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	before := time.Now().Unix()
	reg.Value = validTXT
	if err := DB.Update(reg.ACMETxtPost); err != nil {
		t.Fatalf("Update failed: [%v]", err)
	}

	info, err = DB.GetDomain(reg.Subdomain)
	if err != nil {
		t.Fatalf("GetDomain failed: [%v]", err)
	}
	if !info.HasTXT() {
		t.Errorf("Expected TXT value after update")
	}
	if info.LastUpdate() < before {
		t.Errorf("Expected last update >= %d, got %d", before, info.LastUpdate())
	}
	// Records are ordered by LastUpdate descending, so the updated value comes first
	if info.TXT[0].Value != validTXT {
		t.Errorf("Expected first TXT record to be %q, got %q", validTXT, info.TXT[0].Value)
	}
	if info.TXT[1].Value != "" || info.TXT[1].LastUpdate != 0 {
		t.Errorf("Expected second TXT record to be untouched, got %+v", info.TXT[1])
	}

	_, err = DB.GetDomain("does-not-exist")
	if !errors.Is(err, acmedns.ErrDomainNotFound) {
		t.Errorf("Expected ErrDomainNotFound, got [%v]", err)
	}
}

func TestListDomains(t *testing.T) {
	for i := 0; i < 3; i++ {
		if _, err := DB.Register(acmedns.CIDRSlice{}); err != nil {
			t.Fatalf("Registration failed, got error [%v]", err)
		}
	}
	total, err := DB.CountDomains()
	if err != nil {
		t.Fatalf("CountDomains failed: [%v]", err)
	}

	all, err := DB.ListDomains(total+10, 0)
	if err != nil {
		t.Fatalf("ListDomains failed: [%v]", err)
	}
	if len(all) != total {
		t.Fatalf("Expected %d domains, got %d", total, len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Subdomain >= all[i].Subdomain {
			t.Errorf("Expected domains to be sorted by subdomain, got %s before %s", all[i-1].Subdomain, all[i].Subdomain)
		}
	}
	for _, info := range all {
		if len(info.TXT) != 2 {
			t.Errorf("Expected 2 TXT records for %s, got %d", info.Subdomain, len(info.TXT))
		}
	}

	page, err := DB.ListDomains(2, 1)
	if err != nil {
		t.Fatalf("ListDomains failed: [%v]", err)
	}
	if len(page) != 2 {
		t.Fatalf("Expected page of 2 domains, got %d", len(page))
	}
	if page[0].Subdomain != all[1].Subdomain || page[1].Subdomain != all[2].Subdomain {
		t.Errorf("Unexpected page content: got %s, %s expected %s, %s", page[0].Subdomain, page[1].Subdomain, all[1].Subdomain, all[2].Subdomain)
	}

	empty, err := DB.ListDomains(10, total+100)
	if err != nil {
		t.Fatalf("ListDomains failed: [%v]", err)
	}
	if len(empty) != 0 {
		t.Errorf("Expected empty page, got %d entries", len(empty))
	}
}

func TestGetDomainActivity(t *testing.T) {
	updated, err := DB.Register(acmedns.CIDRSlice{})
	if err != nil {
		t.Fatalf("Registration failed, got error [%v]", err)
	}
	untouched, err := DB.Register(acmedns.CIDRSlice{})
	if err != nil {
		t.Fatalf("Registration failed, got error [%v]", err)
	}
	updated.Value = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := DB.Update(updated.ACMETxtPost); err != nil {
		t.Fatalf("Update failed: [%v]", err)
	}

	activity, err := DB.GetDomainActivity()
	if err != nil {
		t.Fatalf("GetDomainActivity failed: [%v]", err)
	}
	total, _ := DB.CountDomains()
	if len(activity) != total {
		t.Errorf("Expected %d activity entries, got %d", total, len(activity))
	}
	var foundUpdated, foundUntouched bool
	for _, act := range activity {
		switch act.Subdomain {
		case updated.Subdomain:
			foundUpdated = true
			if !act.HasTXT || act.LastUpdate == 0 {
				t.Errorf("Expected updated domain to have TXT and last update, got %+v", act)
			}
		case untouched.Subdomain:
			foundUntouched = true
			if act.HasTXT || act.LastUpdate != 0 {
				t.Errorf("Expected untouched domain to have no TXT and no last update, got %+v", act)
			}
		}
	}
	if !foundUpdated || !foundUntouched {
		t.Errorf("Expected both registered domains in activity, found updated=%v untouched=%v", foundUpdated, foundUntouched)
	}
}

func TestAdminQueryErrors(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Could not create sqlmock: %v", err)
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(mockDB)
	oldDb := DB.GetBackend()
	DB.SetBackend(mockDB)
	defer DB.SetBackend(oldDb)

	mock.ExpectQuery("SELECT COUNT").WillReturnError(errors.New("count error"))
	if _, err := DB.CountDomains(); err == nil {
		t.Errorf("Expected error from CountDomains, got none")
	}

	mock.ExpectQuery("SELECT r.Username").WillReturnError(errors.New("list error"))
	if _, err := DB.ListDomains(10, 0); err == nil {
		t.Errorf("Expected error from ListDomains, got none")
	}

	mock.ExpectQuery("SELECT r.Username").WillReturnError(errors.New("get error"))
	if _, err := DB.GetDomain("whatever"); err == nil {
		t.Errorf("Expected error from GetDomain, got none")
	}

	mock.ExpectQuery("SELECT r.Subdomain").WillReturnError(errors.New("activity error"))
	if _, err := DB.GetDomainActivity(); err == nil {
		t.Errorf("Expected error from GetDomainActivity, got none")
	}

	// Scan errors: wrong column count and invalid username
	mock.ExpectQuery("SELECT r.Username").WillReturnRows(sqlmock.NewRows([]string{"Only one"}).AddRow("value"))
	if _, err := DB.ListDomains(10, 0); err == nil {
		t.Errorf("Expected scan error from ListDomains, got none")
	}
	mock.ExpectQuery("SELECT r.Username").WillReturnRows(
		sqlmock.NewRows([]string{"Username", "Subdomain", "AllowFrom", "Value", "LastUpdate"}).
			AddRow("not-a-uuid", "sub", "[]", "", 0))
	if _, err := DB.ListDomains(10, 0); err == nil {
		t.Errorf("Expected invalid username error from ListDomains, got none")
	}
	mock.ExpectQuery("SELECT r.Subdomain").WillReturnRows(sqlmock.NewRows([]string{"Only one"}).AddRow("value"))
	if _, err := DB.GetDomainActivity(); err == nil {
		t.Errorf("Expected scan error from GetDomainActivity, got none")
	}

	// Rows with NULL txt columns and broken AllowFrom JSON are tolerated
	mock.ExpectQuery("SELECT r.Username").WillReturnRows(
		sqlmock.NewRows([]string{"Username", "Subdomain", "AllowFrom", "Value", "LastUpdate"}).
			AddRow("a097455b-52cc-4569-90c8-7a4b97c6eba8", "sub", "not json", nil, nil))
	infos, err := DB.ListDomains(10, 0)
	if err != nil {
		t.Fatalf("Unexpected error from ListDomains: %v", err)
	}
	if len(infos) != 1 || len(infos[0].TXT) != 0 || len(infos[0].AllowFrom) != 0 {
		t.Errorf("Unexpected result for NULL txt row: %+v", infos)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet sqlmock expectations: %v", err)
	}
}

func TestDeleteDomain(t *testing.T) {
	reg, err := DB.Register(acmedns.CIDRSlice{})
	if err != nil {
		t.Fatalf("Registration failed, got error [%v]", err)
	}
	reg.Value = "ddddddddddddddddddddddddddddddddddddddddddd"
	if err := DB.Update(reg.ACMETxtPost); err != nil {
		t.Fatalf("Update failed: [%v]", err)
	}
	before, _ := DB.CountDomains()

	if err := DB.DeleteDomain(reg.Subdomain); err != nil {
		t.Fatalf("DeleteDomain failed: [%v]", err)
	}
	after, _ := DB.CountDomains()
	if after != before-1 {
		t.Errorf("Expected count to drop from %d to %d, got %d", before, before-1, after)
	}
	if _, err := DB.GetDomain(reg.Subdomain); !errors.Is(err, acmedns.ErrDomainNotFound) {
		t.Errorf("Expected ErrDomainNotFound after delete, got [%v]", err)
	}
	if _, err := DB.GetByUsername(reg.Username); err == nil {
		t.Errorf("Expected user lookup to fail after delete")
	}
	txts, err := DB.GetTXTForDomain(reg.Subdomain)
	if err != nil {
		t.Fatalf("GetTXTForDomain failed: [%v]", err)
	}
	if len(txts) != 0 {
		t.Errorf("Expected TXT rows to be removed, got %v", txts)
	}

	if err := DB.DeleteDomain(reg.Subdomain); !errors.Is(err, acmedns.ErrDomainNotFound) {
		t.Errorf("Expected ErrDomainNotFound for second delete, got [%v]", err)
	}
	if err := DB.DeleteDomain("does-not-exist"); !errors.Is(err, acmedns.ErrDomainNotFound) {
		t.Errorf("Expected ErrDomainNotFound for unknown domain, got [%v]", err)
	}
}

func TestDeleteDomainErrors(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Could not create sqlmock: %v", err)
	}
	defer func(db *sql.DB) {
		_ = db.Close()
	}(mockDB)
	oldDb := DB.GetBackend()
	DB.SetBackend(mockDB)
	defer DB.SetBackend(oldDb)

	mock.ExpectBegin().WillReturnError(errors.New("begin error"))
	if err := DB.DeleteDomain("sub"); err == nil {
		t.Errorf("Expected begin error, got none")
	}

	mock.ExpectBegin()
	mock.ExpectExec("DELETE FROM records").WillReturnError(errors.New("exec error"))
	mock.ExpectRollback()
	if err := DB.DeleteDomain("sub"); err == nil {
		t.Errorf("Expected exec error, got none")
	}

	mock.ExpectBegin()
	mock.ExpectExec("DELETE FROM records").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM txt").WillReturnError(errors.New("txt error"))
	mock.ExpectRollback()
	if err := DB.DeleteDomain("sub"); err == nil {
		t.Errorf("Expected txt exec error, got none")
	}

	mock.ExpectBegin()
	mock.ExpectExec("DELETE FROM records").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DELETE FROM txt").WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()
	if err := DB.DeleteDomain("sub"); err != nil {
		t.Errorf("Expected successful delete, got [%v]", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet sqlmock expectations: %v", err)
	}
}
