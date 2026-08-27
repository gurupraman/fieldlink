package db

import "testing"

func TestValidateStatement_Allowed(t *testing.T) {
	ok := []string{
		"SELECT * FROM t",
		"  select id, name from t where x = 1  ",
		"SELECT * FROM t;",
		"SELECT * FROM t;  ",
		"WITH cte AS (SELECT 1) SELECT * FROM cte",
		"select * from t where s = ';'",          // semicolon inside a string literal
		"select * from t where s = 'it''s fine'", // escaped quote inside a literal
		"SELECT 1 -- trailing comment; DROP TABLE x",
		"SELECT /* inline */ 1 FROM t",
		`SELECT "weird;column" FROM t`,
	}
	for _, s := range ok {
		if err := ValidateStatement(s); err != nil {
			t.Errorf("ValidateStatement(%q) = %v, want allowed", s, err)
		}
	}
}

func TestValidateStatement_Rejected(t *testing.T) {
	bad := []string{
		"",
		"   ",
		"INSERT INTO t VALUES (1)",
		"UPDATE t SET x = 1",
		"DELETE FROM t",
		"DROP TABLE t",
		"EXEC sp_who",
		"SELECT 1; DROP TABLE t",
		"SELECT 1; SELECT 2",
		"  ; SELECT 1",
		"SELECT 1 /* */; DELETE FROM t",
	}
	for _, s := range bad {
		if err := ValidateStatement(s); err == nil {
			t.Errorf("ValidateStatement(%q) = nil, want rejected", s)
		}
	}
}

func TestStripCommentsAndLiterals(t *testing.T) {
	cases := map[string]string{
		"SELECT 1 -- comment": "SELECT 1 ",
		"SELECT /* c */ 1":    "SELECT  1",
		"SELECT 'a;b'":        "SELECT  ",
		"SELECT 'it''s'":      "SELECT  ",
		`SELECT "col;name"`:   `SELECT  `,
	}
	for in, want := range cases {
		got := stripCommentsAndLiterals(in)
		if got != want {
			t.Errorf("stripCommentsAndLiterals(%q) = %q, want %q", in, got, want)
		}
	}
}
