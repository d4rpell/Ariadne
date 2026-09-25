// Package schema holds the versioned input format contracts. The prisma-v1
// contract (columns, order, version and hard limits) is normative in ADR-0007
// and ADR-0008; it is not a claim of equivalence with any vendor export.
package schema

// PrismaV1Selector is the adapter name that selects the prisma-v1 format.
const PrismaV1Selector = "prisma-v1"

// PrismaV1Version is the only supported prisma-v1 schema version.
const PrismaV1Version = "1.0"

// Hard input limits. Field and record budgets count raw CSV bytes consumed from
// the stream, excluding the outer record terminator (ADR-0008 D1).
const (
	PrismaV1MaxFileBytes   = 64 * 1024 * 1024
	PrismaV1MaxDataRecords = 100_000
	PrismaV1MaxFields      = 32
	PrismaV1MaxFieldBytes  = 64 * 1024
	PrismaV1MaxRecordBytes = 256 * 1024
)

// Column describes one canonical prisma-v1 column.
type Column struct {
	Name     string
	Required bool
}

// PrismaV1Columns returns the canonical columns in order. The array is returned
// by value so callers cannot mutate shared state.
func PrismaV1Columns() [15]Column {
	return [15]Column{
		{Name: "schema_version", Required: true},
		{Name: "vulnerability_id", Required: true},
		{Name: "package_name", Required: true},
		{Name: "installed_version", Required: true},
		{Name: "fix_status", Required: true},
		{Name: "image_registry", Required: true},
		{Name: "image_repository", Required: true},
		{Name: "image_tag"},
		{Name: "package_type"},
		{Name: "package_id"},
		{Name: "path"},
		{Name: "severity"},
		{Name: "description"},
		{Name: "published_date"},
		{Name: "discovery_date"},
	}
}
