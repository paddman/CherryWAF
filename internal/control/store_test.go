package control

import (
	"strings"
	"testing"
)

func TestStoreSetupAuthenticationAndAdminSafety(t *testing.T) {
	st, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	admin, err := st.createInitialAdmin("Admin", "Primary Admin", "CherryWAF-Admin-2026!")
	if err != nil {
		t.Fatal(err)
	}
	if !st.setupCompleted() || admin.Role != RoleAdmin || admin.Username != "admin" {
		t.Fatalf("unexpected initial admin: %#v", admin)
	}
	if _, err := st.authenticate("admin", "wrong", "127.0.0.1"); err == nil {
		t.Fatal("wrong password was accepted")
	}
	if _, err := st.authenticate("admin", "CherryWAF-Admin-2026!", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	viewer, err := st.createUser("viewer", "Read Only", "CherryWAF-Viewer-2026!", RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	newRole := RoleViewer
	if _, err := st.updateUser(admin.ID, userUpdate{Role: &newRole}, admin.ID); err == nil || !strings.Contains(err.Error(), "own admin role") {
		t.Fatalf("self-demotion was not rejected: %v", err)
	}
	if err := st.deleteUser(admin.ID, admin.ID); err == nil {
		t.Fatal("self-deletion was accepted")
	}
	if err := st.deleteUser(viewer.ID, admin.ID); err != nil {
		t.Fatal(err)
	}
}

func TestBlankPasswordUpdateDoesNotInvalidateExistingSessions(t *testing.T) {
	st, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	admin, err := st.createInitialAdmin("admin", "Admin", "CherryWAF-Admin-2026!")
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := st.createUser("viewer", "Viewer", "CherryWAF-Viewer-2026!", RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := st.createSession(viewer.ID)
	if err != nil {
		t.Fatal(err)
	}
	empty := ""
	name := "Updated Viewer"
	if _, err := st.updateUser(viewer.ID, userUpdate{DisplayName: &name, Password: &empty}, admin.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := st.sessionPrincipal(sess.Token); !ok {
		t.Fatal("blank password update invalidated an unrelated user session")
	}
}
