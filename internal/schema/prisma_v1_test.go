package schema

import "testing"

func TestPrismaV1ColumnsAreExactAndOrdered(t *testing.T) {
	want := [15]struct {
		name     string
		required bool
	}{
		{"schema_version", true},
		{"vulnerability_id", true},
		{"package_name", true},
		{"installed_version", true},
		{"fix_status", true},
		{"image_registry", true},
		{"image_repository", true},
		{"image_tag", false},
		{"package_type", false},
		{"package_id", false},
		{"path", false},
		{"severity", false},
		{"description", false},
		{"published_date", false},
		{"discovery_date", false},
	}
	columns := PrismaV1Columns()
	for i, column := range want {
		if columns[i].Name != column.name || columns[i].Required != column.required {
			t.Fatalf("column %d = %+v, want %+v", i, columns[i], column)
		}
	}
}

func TestPrismaV1ColumnsAreCopies(t *testing.T) {
	columns := PrismaV1Columns()
	columns[0].Name = "mutated"
	columns[0].Required = false
	fresh := PrismaV1Columns()
	if fresh[0].Name != "schema_version" || !fresh[0].Required {
		t.Fatalf("descriptor state leaked between calls: %+v", fresh[0])
	}
}

func TestPrismaV1ConstantsAreExact(t *testing.T) {
	if PrismaV1Selector != "prisma-v1" || PrismaV1Version != "1.0" {
		t.Fatalf("selector/version = %q/%q", PrismaV1Selector, PrismaV1Version)
	}
	if PrismaV1MaxFileBytes != 64*1024*1024 ||
		PrismaV1MaxDataRecords != 100_000 ||
		PrismaV1MaxFields != 32 ||
		PrismaV1MaxFieldBytes != 64*1024 ||
		PrismaV1MaxRecordBytes != 256*1024 {
		t.Fatalf("limits changed: %d/%d/%d/%d/%d",
			PrismaV1MaxFileBytes, PrismaV1MaxDataRecords, PrismaV1MaxFields,
			PrismaV1MaxFieldBytes, PrismaV1MaxRecordBytes)
	}
}
