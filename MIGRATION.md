# Migration Guide

This document helps users migrate from the legacy tools (`cg_assessment` and `minibva`) to the unified `gauge` tool.

## Overview

The new unified tool (`gauge`) consolidates two previous tools:
- **cg_assessment**: Vulnerability assessment summary generator (HTML/PDF)
- **minibva**: Vulnerability cost analysis tool (XLSX ROI)

Both output types are now available through a single, well-engineered CLI.

## Key Improvements

### Architecture
- **Modular design**: Clean separation of concerns
- **Type safety**: Comprehensive type hints throughout
- **Better error handling**: Clear, actionable error messages
- **Improved logging**: Structured logging with progress indicators

### Performance
- **Faster caching**: Improved digest-based caching system
- **Better parallelism**: Optimized thread pool management
- **Reduced memory**: Efficient streaming of scan results

### Usability
- **Unified CLI**: Single tool for both output types (assessment summary and cost analysis)
- **Auto-detection**: Output type detected from file extension
- **Better help**: Comprehensive --help documentation
- **Consistent naming**: Standardized argument names

## Migration Steps

### Step 1: Install New Tool

```bash
cd gauge
pip install -r requirements.txt

# Optional: Install as package
pip install -e .
```

### Step 2: Update Scripts

#### From `cg_assessment` (Vulnerability Assessment Summary - HTML)

**Old Command:**
```bash
python3 cve_scanner.py \\
  -s images.csv \\
  -o report.html \\
  -e exec-summary.md \\
  -a appendix.md \\
  -c "Acme Corp" \\
  --max-workers 8
```

**New Command:**
```bash
python -m gauge \\
  -s images.csv \\
  -o report.html \\
  --format html \\
  -e exec-summary.md \\
  -a appendix.md \\
  -c "Acme Corp" \\
  --max-workers 8
```

**Changes:**
- Use `python -m gauge` instead of `python3 cve_scanner.py`
- Add `--format html` (optional if output has .html extension)
- All other arguments remain the same

#### From `minibva` (Vulnerability Cost Analysis - XLSX)

**Old Command:**
```bash
python3 minibva.py \\
  --customername "Acme Corp" \\
  --list images.txt \\
  --vulnhours 3 \\
  --hourlyrate 100 \\
  --fips 5
```

**New Command:**
```bash
python -m gauge \\
  -s images.txt \\
  -o "Acme Corp Image Comparison (ROI).xlsx" \\
  --format xlsx \\
  --customer "Acme Corp" \\
  --hours-per-vuln 3 \\
  --hourly-rate 100 \\
  --fips-count 5
```

**Changes:**
- Use `python -m gauge` instead of `python3 minibva.py`
- `-s` instead of `--list` (same file format)
- Explicit `-o` for output path (was auto-generated before)
- `--customer` instead of `--customername`
- `--hours-per-vuln` instead of `--vulnhours`
- `--hourly-rate` instead of `--hourlyrate`
- `--fips-count` instead of `--fips`
- Add `--format xlsx` (optional if output has .xlsx extension)

### Step 3: Update Input Files (if needed)

Both tools used the same CSV format, so no changes needed:

```csv
alternative_image,chainguard_image
python:3.12,cgr.dev/chainguard-private/python:latest
nginx:1.25,cgr.dev/chainguard-private/nginx:latest
```

## Argument Mapping

### Common Arguments

| Old (both tools) | New | Notes |
|------------------|-----|-------|
| `-s` / `--source` / `--list` | `-s` / `--source` | Standardized to `--source` |
| `-c` / `--customername` | `-c` / `--customer` | Standardized to `--customer` |
| `--max-workers` | `--max-workers` | No change |

### HTML-Specific Arguments

| Old (`cg_assessment`) | New | Notes |
|----------------------|-----|-------|
| `-e` / `--exec-summary` | `-e` / `--exec-summary` | No change |
| `-a` / `--appendix` | `-a` / `--appendix` | No change |
| `--platform` | `--platform` | No change |
| `--cache-dir` | `--cache-dir` | No change |
| `--no-cache` | `--no-cache` | No change |
| `--clear-cache` | `--clear-cache` | No change |

### XLSX-Specific Arguments

| Old (`minibva`) | New | Notes |
|----------------|-----|-------|
| `--vulnhours` | `--hours-per-vuln` | More descriptive name |
| `--hourlyrate` | `--hourly-rate` | Hyphenated for consistency |
| `--fips` | `--fips-count` | More explicit |
| - | `--auto-detect-fips` | New feature! |

## Feature Parity

### All Features Preserved

✅ **Vulnerability Assessment Summaries (HTML)**
- Executive summary support
- Custom appendix
- Chainguard branding
- PDF optimization
- Template variables
- Vulnerability comparison metrics

✅ **Vulnerability Cost Analysis (XLSX)**
- ROI calculations
- CVE backlog remediation costs
- Future CVE cost projections
- FIPS implementation cost analysis
- Interactive formulas

### New Features

🎉 **Auto-detect FIPS images**
```bash
--auto-detect-fips  # Automatically detects FIPS images from names
```

🎉 **Better cache management**
- Improved cache hit rates
- Faster cache lookups
- Portable cache files

🎉 **Enhanced logging**
- Structured log messages
- Progress indicators
- Cache statistics

## Output Compatibility

### Vulnerability Assessment Summaries (HTML)
- **100% compatible** with previous `cg_assessment` output
- Same styling and layout
- Same PDF conversion process
- Same vulnerability metrics and comparisons

### Vulnerability Cost Analysis (XLSX)
- **100% compatible** with previous `minibva` output
- Same formulas and calculations
- Same worksheet layout
- Same ROI and cost analysis methodology
- Can open old and new files side-by-side

## Batch Migration Script

If you have many scripts using the old tools, here's a helper to migrate them:

```bash
#!/bin/bash
# migrate-commands.sh

# Function to convert old cg_assessment commands
migrate_cg_assessment() {
    sed 's/python3 cve_scanner.py/python -m gauge --format html/g' "$1"
}

# Function to convert old minibva commands
migrate_minibva() {
    sed 's/python3 minibva.py/python -m gauge --format xlsx/g' "$1" | \\
    sed 's/--customername/--customer/g' | \\
    sed 's/--vulnhours/--hours-per-vuln/g' | \\
    sed 's/--hourlyrate/--hourly-rate/g' | \\
    sed 's/--fips /--fips-count /g'
}

# Usage:
# migrate_cg_assessment old-script.sh > new-script.sh
# migrate_minibva old-script.sh > new-script.sh
```

## Testing Migration

### 1. Run Side-by-Side Comparison

```bash
# Old tool
python3 cve_scanner.py -s test.csv -o old-report.html

# New tool
python -m gauge -s test.csv -o new-report.html

# Compare outputs (should be nearly identical)
diff old-report.html new-report.html
```

### 2. Verify XLSX Calculations

```bash
# Old tool
python3 minibva.py --list test.txt --customername "Test" --output old.xlsx

# New tool
python -m gauge -s test.txt -o new.xlsx --customer "Test"

# Open both in Excel/LibreOffice and compare
```

## Rollback Plan

If you need to rollback:

1. **Keep old tools**: Don't delete `cg_assessment` or `minibva` directories
2. **Test in parallel**: Run both old and new tools side-by-side
3. **Gradual migration**: Migrate one script at a time
4. **Validate outputs**: Compare old vs new reports before switching

## Support

### Common Migration Issues

**Issue: "Module not found: gauge"**
- Solution: Ensure you're in the correct directory
- Solution: Run `pip install -e .` to install as package

**Issue: "Different cache behavior"**
- Solution: Use `--clear-cache` to start fresh
- Note: New cache is more efficient, may produce different cache statistics

**Issue: "Slightly different XLSX output"**
- Expected: Minor formatting improvements
- Formulas: Identical calculations, possibly better organized

**Issue: "Missing features"**
- Contact: If any feature is missing, this is a bug - please report!

### Getting Help

1. Check this migration guide
2. Review `README.md` for detailed documentation
3. Use `python -m gauge --help` for CLI reference
4. Contact your Chainguard representative

## Benefits Summary

### Why Migrate?

✅ **Better Performance**
- Faster scanning with improved caching
- Optimized parallel execution
- Reduced memory usage

✅ **Improved Reliability**
- Better error handling
- Type-safe code
- Comprehensive logging

✅ **Easier Maintenance**
- Single tool to maintain
- Modular architecture
- Well-documented code

✅ **Better UX**
- Consistent CLI interface
- Auto-detection features
- Clear progress indicators

### Timeline Recommendation

- **Week 1**: Install new tool, test with sample data
- **Week 2**: Migrate non-critical scripts
- **Week 3**: Migrate production scripts with validation
- **Week 4**: Full cutover, archive old tools

---

**Questions?** Contact your Chainguard representative for migration assistance.
