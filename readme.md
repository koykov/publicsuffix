# Mozilla Public Suffix List database

MPSL is a domain parser based on [Mozilla's public suffix list](https://publicsuffix.org/).

Domain to parse may contain the following parts:
* Top level domain (TLD) - the last part of the domain that doesn't contain a dots (example: com, org, ...).
* Effective TLD (eTLD) - the last part that contains arbitrary count of the dots (example: co.uk, cdn.prod.atlassian-dev.net, ...).
* Effective TLD plus one (eTLD+1) - eTLD + domain name (or first subdomain).
* ICANN flag - is TLD/eTLD provided by public ICANN list.

This package provides a possibility to get all parts at once or get them separately by call corresponding methods (see below).

## Installation

The package requires access to pre-downloaded [public suffix database](https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat)
or URL to the list file to fetch it on the fly (preferred way is to give URL to full PSL database).

There is three ways to initialize the database:
```go
db, err := mpsl.New(hasher)
// way 1: load from local file
err = db.Load("/path/to/psl/file")
// way 2: fetch from remote URL
err = db.Fetch("http://url/to/psl/file") // or FetchFull() to fetch official PSL file.
// way 3: load from local file (if file's mod time is less than expire) or fetch from remote URL (and save result to the local file).
err = db.LoadOrFetchIf("/path/to/psl/file", "http://url/to/psl/file", time.Hour * 24) // or LoadOrFetchFullIf(...).
```

All PSL data will be stored in special storage optimized for fast access and minimal pointers count (three pointers in fact).

## Usage

After initialization database will ready to parse the domains:
```go
domain := "a.b.c.amazon.co.uk"
tld, icann := db.GetTLDStr(domain) // "uk", true
etld := db.GetEffectiveTLDStr(domain) // "co.uk"
etld1 := db.GetEffectiveTLDPlusOneStr(domain) // "amazon.co.uk"
// or get all parts at once
tld, etld, etld1, icann := db.ParseStr(domain) // the same data ...
```
