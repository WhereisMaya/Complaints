# Complaints Tracker

A local-first, single-page JS/HTML app to track complaints, SARs, escalations, and legal actions. It supports per-user data separation, attachments (IndexedDB), redacted views/exports, escalation templates, calendar, and CSV/JSON/iCal/TXT exports.

## Quick start

1. Open `ComplaintsTracker/index.html` in a modern browser (Chrome/Edge/Safari/Firefox).
2. Optional: Use Secure Login (top-right) or test login:
   - admin / admin123 (bundled dataset)
   - AAAPPP / AAA123 (separate user store with seeded examples)
3. Add complaints in the Add tab. Use filters and search on the Dashboard.

No server is required; data is stored in localStorage and IndexedDB per user.

## Features

- Dashboard metrics, filters (institution, status, type, keyword, date-range), saved segments
- Open Entries (complaints + SARs) with quick open
- All Complaints grouping by Institution
- Complaint Details
  - Concerns (notes, responses, evidence URLs, files), history with tamper-evident hashes
  - Share Concerns (PSA/CQC/custom) via prefilled email/copy
  - Escalation Template (IOPC/ICO/PHSO/PSA based on type)
  - Chaser and Closure modals, legal escalation, edit/delete
  - Exports: Markdown, Notebook (.ipynb), print to PDF
- SAR panel (28‑day due date, overdue chip, ICO escalation template, completion, missed-response logs, ICO ref)
- Calendar (color-coded open/escalated/resolved days) with click-to-view events
- Institutions tab (search, add/edit/delete local overrides, case counts, CSV import/export)
- Redaction
  - Redact View toggle for masked viewing
  - Redaction Controls per-field and safe attachments for redacted exports
  - Share Redacted standalone HTML
- Customization
  - Presets (Midnight, Ocean, Forest, Sunset, Slate, Mint, Rose, Amber, High Contrast)
  - Header/Tab color, Panel/Card color, background overrides, font dropdown, size, contrast/spacing
- Exports
  - JSON bundle (per user), CSV, TXT/Markdown, iCal, print to PDF

## Data storage

- Per-user storage namespaces in localStorage:
  - `complaintsTracker.complaints.v1:<username>`
  - `complaintsTracker.sars.v1:<username>`
  - `complaintsTracker.phso.v1:<username>`
  - `complaintsTracker.legal.v1:<username>`
  - `complaintsTracker.accountability.v1:<username>`
- Users and session (global):
  - `complaintsTracker.users.v1`
  - `complaintsTracker.session.v1`
- Attachments: IndexedDB database `complaints-tracker-idb`, store `files`

## Security & redaction

- Optional local login (demo-grade). For production, add a backend API and JWT auth.
- Redaction masks emails, phone numbers, badge/employee numbers, and ID-like tokens; controls allow per-field override and safe attachment selection.

## Development

- Pure JS/HTML/CSS (no build step). Edits apply on refresh.
- Favicon: `ComplaintsTracker/favicon.ico` linked as `favicon.ico` in `index.html`.
- Styling is themeable via CSS variables: `--bg`, `--elev`, `--header-bg`, `--text`, `--accent`, etc.

## Keyboard & accessibility

- Tabs are buttons; forms and lists are keyboard navigable. Custom settings include contrast/spacing. Further ARIA roles can be added if required.

## Known limitations

- Redaction of attachments (binary/PDF/image) is not automatic; mark safe attachments via controls or exclude them from redacted exports.
- Demo login stores data locally in the browser; clear storage to reset.

## Roadmap ideas

- Server sync (JWT), multi-user collaboration, role-based permissions
- Full-text search index, tag system, case severity scoring/priority views
- More calendar controls (open-only toggle in UI)

## License

MIT (adjust as needed).
