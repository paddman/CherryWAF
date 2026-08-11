package control

import "testing"

func TestPasswordHashAndPolicy(t *testing.T) {
	for _, password := range []string{"short", "alllowercase123!", "ALLUPPERCASE123!", "NoNumberHere!", "NoSymbol1234"} {
		if err := validatePassword(password); err == nil {
			t.Fatalf("weak password %q was accepted", password)
		}
	}
	const password = "CherryWAF-Strong-2026!"
	hash, err := hashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword(hash, password) {
		t.Fatal("valid password did not verify")
	}
	if verifyPassword(hash, password+"x") {
		t.Fatal("wrong password verified")
	}
}
