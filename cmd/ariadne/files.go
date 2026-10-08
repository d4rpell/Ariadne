package main

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
)

// First filesystem frontier of the project (ADR-0023 §6/§7, R-02 resolved). Only
// this package opens and closes paths; every route is interpreted against the
// captured working directory, without home, environment or glob expansion, and
// the ratified profile rejects the observed forms it can recognise. It is not a
// sandbox and it does not promise to detect remote mounts or directory-swap
// races; those limits are declared in the record, not hidden here.

// transport bounds of R-01: reading asks for at most N+1 bytes, so an excess is
// observed without trusting Stat.
const (
	maxBundleInputBytes  = 128 << 20
	maxContextInputBytes = 256 << 10
	maxInputDepth        = 32
)

// isTimeout recognises an observed IO timeout. Unknown failures are never
// upgraded to it: the transport layer only reports what it can name.
func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var timed interface{ Timeout() bool }
	if errors.As(err, &timed) {
		return timed.Timeout()
	}
	return false
}

// classifyRead names one read-side failure per ADR-0023 §5: an observed timeout
// precedes permission and not-found; the rest are read failures, never a missing
// file.
func classifyRead(err error) string {
	switch {
	case err == nil:
		return ""
	case isTimeout(err):
		return codeTimeout
	case errors.Is(err, fs.ErrPermission):
		return codePermissionDenied
	case errors.Is(err, fs.ErrNotExist):
		return codeNotFound
	default:
		return codeReadFailure
	}
}

// classifyClose names the failure of closing an input. The contract assigns
// every close error to read_failure — a close is not an open, so a permission or
// existence story does not apply — except an identifiable timeout, which keeps
// its own name.
func classifyClose(err error) string {
	if isTimeout(err) {
		return codeTimeout
	}
	return codeReadFailure
}

// classifyCreate names one create-side failure per ADR-0023 §5: timeout before
// permission and existence; a missing parent is a write failure because this
// profile never creates directories.
func classifyCreate(err error) string {
	switch {
	case err == nil:
		return ""
	case isTimeout(err):
		return codeTimeout
	case errors.Is(err, fs.ErrPermission):
		return codePermissionDenied
	case errors.Is(err, fs.ErrExist):
		return codeAlreadyExists
	default:
		return codeWriteFailure
	}
}

// sourceFile is the read side the runner uses. It exists so the tests can
// observe Close failures and observed timeouts deterministically; production
// always opens a regular file with openSource.
type sourceFile interface {
	io.Reader
	io.Closer
	Stat() (os.FileInfo, error)
}

var openSource = func(path string) (sourceFile, error) {
	return os.Open(path) //nolint:gosec // path validated by resolveRoute (fs boundary R-02): regular file only, no symlink/device/FIFO
}

// readInput reads one bounded input. The route is resolved exactly once and the
// same resolved path is used for inspection and for the open, so the walked
// components and the opened file are always the same file. The type is decided
// before the open — opening a FIFO or a device can block or have effects — and
// confirmed with the opened descriptor, which is the authority; the bound is
// enforced by asking for one byte more than the ratified limit, and the JSON
// depth is counted on the raw bytes before any decoder sees them.
func readInput(path, stage string, limit int64, checkDepth bool, cwd string) ([]byte, *cliError) {
	resolved, failure := resolveRoute(path, stage, cwd)
	if failure != nil {
		return nil, failure
	}
	if info, err := os.Lstat(resolved); err == nil { //nolint:gosec // resolved came from resolveRoute (fs boundary R-02), the only open path
		if !info.Mode().IsRegular() {
			return nil, newFailure(stage, codeInvalidFile)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		// A path that cannot be inspected is not opened: the failure is named.
		return nil, newFailure(stage, classifyRead(err))
	}
	file, err := openSource(resolved)
	if err != nil {
		return nil, newFailure(stage, classifyRead(err))
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, newFailure(stage, classifyRead(err))
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, newFailure(stage, codeInvalidFile)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, newFailure(stage, classifyRead(readErr))
	}
	// A Close failure is a transport failure of the read, never a success with
	// bytes that were not fully delivered, and it is named as such: a close is
	// not an open, so permission and existence stories belong to other stages.
	if closeErr != nil {
		return nil, newFailure(stage, classifyClose(closeErr))
	}
	if int64(len(data)) > limit {
		return nil, newFailure(stage, codeInputLimit)
	}
	if checkDepth {
		if err := strictDepth(data, maxInputDepth); err != nil {
			return nil, newFailure(stage, codeInputLimit)
		}
	}
	return data, nil
}

// destinationFile is the write side the runner uses. It exists so the tests can
// observe short writes, Close failures and non-regular descriptors
// deterministically; production always opens an exclusive regular file with
// createDestination.
type destinationFile interface {
	io.Writer
	io.Closer
	Stat() (os.FileInfo, error)
}

var createDestination = func(path string) (destinationFile, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // path validated by resolveRoute (fs boundary R-02), exclusive create 0600
}

// writeOutput creates the destination exclusively, confirms with the opened
// descriptor that it is a regular file, and transports the already computed
// bytes. The route is resolved exactly once, so the walked components and the
// created file are the same file. Nothing is written before the bytes exist; a
// failure can leave a partial file and that is reported, never cleaned up
// silently.
func writeOutput(path string, data []byte, cwd string) *cliError {
	resolved, failure := resolveRoute(path, stageOutputWrite, cwd)
	if failure != nil {
		return failure
	}
	file, err := createDestination(resolved)
	if err != nil {
		return newFailure(stageOutputWrite, classifyCreate(err))
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return newFailure(stageOutputWrite, classifyCreate(err))
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return newFailure(stageOutputWrite, codeInvalidFile)
	}
	written, err := file.Write(data)
	if err == nil && written != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Close()
	} else {
		_ = file.Close()
	}
	if err != nil {
		if isTimeout(err) {
			return newFailure(stageOutputWrite, codeTimeout)
		}
		return newFailure(stageOutputWrite, codeWriteFailure)
	}
	return nil
}

// deliverStdout transports one stdout delivery of the runner: the receipt, the
// verified line or the help text. It checks the byte count and names an observed
// timeout as itself, so a partial or timed-out delivery is never reported as a
// plain write failure.
func deliverStdout(stdout io.Writer, text string) *cliError {
	written, err := io.WriteString(stdout, text)
	if err == nil && written != len(text) {
		err = io.ErrShortWrite
	}
	if err != nil {
		if isTimeout(err) {
			return newFailure(stageStdoutWrite, codeTimeout)
		}
		return newFailure(stageStdoutWrite, codeWriteFailure)
	}
	return nil
}

// resolveRoute applies the ratified local-path profile and returns the single
// resolved route used afterwards for inspection, for the open and for the
// create. Resolving once is what keeps the walked components and the opened file
// the same file: a drive-rooted Windows spelling such as `\dir\file` passes
// neither through `IsAbs` (false) nor through the same resolution as the open
// (`\dir\file` resolves against the drive root, not against the working
// directory), so that spelling is refused as ambiguous instead of being silently
// reinterpreted. The profile itself rejects UNC and device prefixes, Windows
// alternate streams, reserved device names, and any observed symlink or reparse
// point in any component of the route. Existence and permissions are not decided
// here: they belong to the open that follows.
func resolveRoute(path, stage, cwd string) (string, *cliError) {
	if path == "" {
		return "", newFailure(stage, codeInvalidFile)
	}
	if runtime.GOOS == "windows" {
		if windowsPathProblem(path) {
			return "", newFailure(stage, codeInvalidFile)
		}
		if !filepath.IsAbs(path) && (strings.HasPrefix(path, `\`) || strings.HasPrefix(path, "/")) {
			// Drive-rooted spelling: the open would resolve it against the drive
			// root while the walk resolves it against the working directory.
			return "", newFailure(stage, codeInvalidFile)
		}
	}
	absolute := path
	if !filepath.IsAbs(absolute) {
		absolute = filepath.Join(cwd, path)
	}
	if symlinkComponent(absolute) {
		return "", newFailure(stage, codeInvalidFile)
	}
	return absolute, nil
}

// windowsPathProblem recognises the Windows forms the profile refuses before any
// open: UNC and device namespaces, drive-relative routes and alternate data
// streams, plus the reserved device names as whole components.
func windowsPathProblem(path string) bool {
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `//`) {
		return true
	}
	volume := filepath.VolumeName(path)
	rest := path[len(volume):]
	if volume != "" && rest != "" && !strings.HasPrefix(rest, `\`) && !strings.HasPrefix(rest, "/") {
		return true
	}
	if strings.Contains(rest, ":") {
		return true
	}
	for _, component := range strings.FieldsFunc(rest, func(character rune) bool {
		return character == '\\' || character == '/'
	}) {
		if reservedDeviceName(component) {
			return true
		}
	}
	return false
}

// reservedDeviceName matches the documented reserved device stems. Windows
// ignores any extension and trailing dots or spaces when it resolves them, so
// `CON.txt` and `NUL.` name the same devices, and the console pseudo-files
// CONIN$ and CONOUT$ are reserved as well.
func reservedDeviceName(component string) bool {
	name := strings.ToUpper(component)
	name = strings.TrimRight(name, ". ")
	if cut := strings.IndexByte(name, '.'); cut >= 0 {
		name = name[:cut]
	}
	switch name {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if strings.HasPrefix(name, "COM") || strings.HasPrefix(name, "LPT") {
		rest := name[3:]
		switch rest {
		case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9":
			return true
		case "\u00b9", "\u00b2", "\u00b3":
			// Superscript digits are the same reserved devices.
			return true
		}
	}
	return false
}

// lstatPath is the inspection the walk performs. It exists so a test can place
// a synthetic entry — including one carrying the Windows reparse attribute — in
// front of the walker and prove the walk consults it; production always lists
// with os.Lstat.
var lstatPath = func(path string) (os.FileInfo, error) {
	return os.Lstat(path)
}

// symlinkComponent walks every observed component of the route with Lstat and
// refuses any one that is a link, a reparse point or a special file. Missing
// components are not a policy failure: they are absence, and the open that
// follows names it. A component that cannot be inspected fails closed.
func symlinkComponent(absolute string) bool {
	for _, prefix := range routePrefixes(absolute) {
		info, err := lstatPath(prefix)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return false
			}
			return true
		}
		if unacceptableMode(info.Mode()) || reparseAttribute(info) {
			return true
		}
	}
	return false
}

// routePrefixes returns the absolute path of every component of the route, from
// the first one below the root to the route itself, preserving the volume root:
// a Windows route is inspected as `C:\dir\file`, never as the drive-relative
// `C:dir\file`, which would resolve against the per-drive working directory.
func routePrefixes(absolute string) []string {
	volume := filepath.VolumeName(absolute)
	rest := absolute[len(volume):]
	windows := runtime.GOOS == "windows"
	rest = strings.TrimLeftFunc(rest, func(character rune) bool {
		return isRouteSeparator(character, windows)
	})
	root := string(filepath.Separator)
	if volume != "" {
		root = volume + string(filepath.Separator)
	}
	prefixes := []string{}
	current := root
	for _, component := range splitRouteComponents(rest, windows) {
		current = filepath.Join(current, component)
		prefixes = append(prefixes, current)
	}
	return prefixes
}

// splitRouteComponents divides one route into its components. The separator set
// is the platform's: on Windows both `/` and `\` divide, while on Unix a
// backslash is an ordinary character of a file name and splitting on it would
// walk a component that does not exist — letting a real link pass uninspected.
func splitRouteComponents(rest string, windows bool) []string {
	return strings.FieldsFunc(rest, func(character rune) bool {
		return isRouteSeparator(character, windows)
	})
}

func isRouteSeparator(character rune, windows bool) bool {
	if character == '/' {
		return true
	}
	return windows && character == '\\'
}

// unacceptableMode reports the modes that must never appear in an observed route
// component. os.Lstat maps a symlink to ModeSymlink and every other Windows
// reparse point it is willing to distinguish — junctions and the remaining tags
// — to ModeIrregular; the special file kinds carry their own bits and are
// refused too, because the ratified policy rejects special files as well. A
// reparse point that Mode() deliberately hides — IO_REPARSE_TAG_DEDUP is
// classified as a regular file by design — is caught by reparseAttribute, which
// reads the attribute bit instead of the mode.
func unacceptableMode(mode os.FileMode) bool {
	return mode&(os.ModeSymlink|os.ModeIrregular|os.ModeDevice|os.ModeCharDevice|os.ModeNamedPipe|os.ModeSocket) != 0
}

// fileAttributeReparsePoint is FILE_ATTRIBUTE_REPARSE_POINT of the Windows API.
const fileAttributeReparsePoint = 0x00000400

// reparseAttribute reports whether the observed entry carries the Windows
// reparse attribute. os.Lstat exposes syscall.Win32FileAttributeData through
// Sys(); reading FileAttributes through reflection keeps the ratified import
// boundary — which forbids syscall in this package — while refusing every
// reparse point as a class, DEDUP included, without having to identify any tag.
// The attribute is what the policy actually protects: a route that crosses any
// reparse point is refused. On platforms without the attribute the answer is
// false, because there are no reparse points to observe; an unreadable attribute
// on Windows fails closed.
func reparseAttribute(info os.FileInfo) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	system := info.Sys()
	if system == nil {
		return true
	}
	return attributesSayReparse(system)
}

// attributesSayReparse reads the FileAttributes field of the value Sys() hands
// out. It is a separate function so the reading rule is testable with synthetic
// values on any platform, while the Windows gate stays in reparseAttribute.
func attributesSayReparse(system any) bool {
	value := reflect.ValueOf(system)
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return true
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return true
	}
	field := value.FieldByName("FileAttributes")
	if !field.IsValid() || !field.CanUint() {
		return true
	}
	return field.Uint()&fileAttributeReparsePoint != 0
}
