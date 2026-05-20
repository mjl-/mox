#!/bin/sh
set -e

# Check for vulnerable dependencies using govulncheck and attempt to auto-fix
# by upgrading modules to their fixed versions.

# Require jq for JSON parsing.
if ! command -v jq >/dev/null 2>&1; then
	echo "ERROR: jq is required but not installed." >&2
	exit 1
fi

# Require govulncheck.
if ! command -v govulncheck >/dev/null 2>&1; then
	echo "ERROR: govulncheck is required but not installed." >&2
	echo "Install with: go install golang.org/x/vuln/cmd/govulncheck@latest" >&2
	exit 1
fi

VULN_OUTPUT="vulncheck-output.json"
VULN_RECHECK="vulncheck-recheck.json"

cleanup() {
	rm -f "$VULN_OUTPUT" "$VULN_RECHECK"
}
trap cleanup EXIT

# Ensure vendor directory is consistent before scanning.
if [ -d vendor ]; then
	echo "Syncing vendor directory..."
	make govendor
fi

echo "Running govulncheck..."
govulncheck -json ./... > "$VULN_OUTPUT" 2>/dev/null

# Extract findings that have a fixed_version (actionable vulnerabilities).
# Each line of the JSON stream is a Message object; filter for those with a "finding" field.

# Module vulnerabilities (fixable via go get module@version).
MODULE_FIXES=$(jq -r '
	select(.finding != null) |
	select(.finding.fixed_version != null) |
	select(.finding.fixed_version != "") |
	select(.finding.trace[0].module != "stdlib") |
	"\(.finding.trace[0].module)@\(.finding.fixed_version)"
' "$VULN_OUTPUT" | sort -u)

# Stdlib vulnerabilities (fixable via go get toolchain@version).
STDLIB_FIXES=$(jq -r '
	select(.finding != null) |
	select(.finding.fixed_version != null) |
	select(.finding.fixed_version != "") |
	select(.finding.trace[0].module == "stdlib") |
	.finding.fixed_version
' "$VULN_OUTPUT" | sort -Vu | tail -n 1)

if [ -z "$MODULE_FIXES" ] && [ -z "$STDLIB_FIXES" ]; then
	# Check if there are any findings at all (including unfixable ones).
	HAS_FINDINGS=$(jq -r 'select(.finding != null) | .finding.osv' "$VULN_OUTPUT" | head -n 1)
	if [ -z "$HAS_FINDINGS" ]; then
		echo "No vulnerabilities found."
		exit 0
	fi

	# Findings exist but none are fixable.
	UNFIXABLE=$(jq -r '
		select(.finding != null) |
		select(.finding.fixed_version == null or .finding.fixed_version == "") |
		.finding.osv
	' "$VULN_OUTPUT" | sort -u)

	if [ -n "$UNFIXABLE" ]; then
		echo "WARNING: Found vulnerabilities with no available fix:"
		echo "$UNFIXABLE"
	fi

	echo "ERROR: Unable to resolve vulnerabilities"
	exit 1
fi

echo "Found vulnerable dependencies. Attempting to fix..."
echo ""

# Upgrade stdlib via toolchain directive if needed.
# govulncheck outputs versions as "v1.X.Y" but go get toolchain@ expects "go1.X.Y".
if [ -n "$STDLIB_FIXES" ]; then
	TOOLCHAIN_VERSION=$(echo "$STDLIB_FIXES" | sed 's/^v/go/')
	echo "  go get toolchain@$TOOLCHAIN_VERSION"
	go get "toolchain@$TOOLCHAIN_VERSION"
fi

# Apply module fixes by upgrading each module to its fixed version.
for fix in $MODULE_FIXES; do
	echo "  go get $fix"
	go get "$fix"
done

echo ""
echo "Running make govendor..."
make govendor

echo "Verifying build..."
if ! go build ./...; then
	echo ""
	echo "ERROR: Unable to resolve vulnerabilities (build failed after upgrade)"
	exit 1
fi

echo "Re-running govulncheck to verify fix..."
govulncheck -json ./... > "$VULN_RECHECK" 2>/dev/null

REMAINING=$(jq -r '
	select(.finding != null) |
	.finding.osv
' "$VULN_RECHECK" | sort -u)

if [ -n "$REMAINING" ]; then
	echo ""
	echo "Remaining vulnerabilities after fix attempt:"
	echo "$REMAINING"
	echo ""
	# TODO: Invoke copilot from the CLI to attempt to resolve remaining issues.
	#   e.g. copilot-cli fix-vulns --input "$VULN_RECHECK"
	echo "ERROR: Unable to resolve vulnerabilities"
	exit 1
fi

echo "All vulnerabilities resolved successfully."
exit 0
