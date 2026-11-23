# Nager.EmailAuthentication

Nager.EmailAuthentication is a .NET library for parsing DMARC, DKIM, and SPF records into structured, easy-to-use data.

- **DMARC** (Domain-based Message Authentication, Reporting, and Conformance) enables domain owners to specify how mail receivers should handle emails that fail authentication.
- **DKIM** (DomainKeys Identified Mail) adds a cryptographic signature to outgoing emails to ensure their authenticity and integrity.
- **SPF** (Sender Policy Framework) specifies which IP addresses are allowed to send email on behalf of a domain.

This library focuses on extracting and interpreting the content of these DNS records, enabling applications to analyze and work with email authentication settings programmatically.

## Features

- Parse DMARC records according to RFC 9989 (DMARCbis), including the tags `np`, `psd` and `t`.
- Parse DKIM Public Key records with comprehensive validation, including the key length.
- Parse DKIM Signatures with comprehensive validation.
- Parse SPF records into mechanisms and modifiers.
- Identify and report errors in DMARC, DKIM and SPF configurations.

## Installation

The package is available on [NuGet](https://www.nuget.org/packages/Nager.EmailAuthentication)
```
PM> install-package Nager.EmailAuthentication
```

or

```
dotnet add package Nager.EmailAuthentication
```

## Examples

### Parsing a DMARC Record

Use `DmarcRecordParser.TryParse` to parse a DMARC record string. The record is interpreted like a mail receiver does
according to RFC 9989: the method returns `true` if mail receivers can apply the record and outputs a `DmarcRecordV1` object.

```cs
var dmarcRecordRaw = "v=DMARC1; p=reject; sp=quarantine; t=y; rua=mailto:dmarc@example.com";
if (DmarcRecordParser.TryParse(dmarcRecordRaw, out var dmarcRecord) && dmarcRecord is DmarcRecordV1 dmarcRecordV1)
{
    Console.WriteLine($"Policy: {dmarcRecordV1.DomainPolicy}");                                  // Reject
    Console.WriteLine($"Policy for subdomains: {dmarcRecordV1.SubdomainPolicy}");                // Quarantine
    Console.WriteLine($"Policy for non-existent subdomains: {dmarcRecordV1.NonExistentSubdomainPolicy}"); // Quarantine
    Console.WriteLine($"Test mode: {dmarcRecordV1.TestMode}");                                   // True
}
```

To find the DMARC record among the TXT records of a domain, use `DmarcRecordParser.IsDmarcRecord`.

### Handling DMARC Validation Errors

The overload with `parsingResults` reports what is wrong with a record. A tag with an invalid value does not make the
record invalid, mail receivers ignore the tag in favor of its default value. The parsing only fails if mail receivers
ignore the whole record, e.g. if it has no valid policy and no URI for aggregate reports.

```cs
var dmarcRecordRaw = "v=DMARC1; p=reject; pct=50; adkim=x; rua=mailto:dmarc@example.com";
var isValid = DmarcRecordParser.TryParse(dmarcRecordRaw, out var dmarcRecord, out var parsingResults);

foreach (var parsingResult in parsingResults ?? [])
{
    // Warning [pct]: Tag is obsolete. Introduced in RFC 7489 and removed in RFC 9989.
    // Error   [adkim]: Wrong config x
    Console.WriteLine(parsingResult);
}
```

The tags `pct`, `rf` and `ri` were removed by RFC 9989, they are reported with a warning.

### Parsing an SPF Record

Use `SpfRecordDataFragmentParserV1.TryParse` to parse an SPF record into its mechanisms and modifiers.
Terms that are neither a mechanism nor a modifier are reported in `parsingResults`.

```cs
var spfRecordRaw = "v=spf1 include:spf.example.com ip4:192.0.2.0/24 -all";
if (SpfRecordDataFragmentParserV1.TryParse(spfRecordRaw, out var spfRecord, out var parsingResults))
{
    foreach (var spfTerm in spfRecord.SpfTerms)
    {
        Console.WriteLine(spfTerm);
    }
}
```

### Parsing a DKIM Public Key Record

Similarly, you can parse a DKIM public key (DNS TXT) record. Use `DkimPublicKeyRecordParser.TryParse` and check for errors:

```cs
string dkimKeyRecord = "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ..."; // Example public key
if (DkimPublicKeyRecordParser.TryParse(dkimKeyRecord, out var publicKeyRecord) && publicKeyRecord is DkimPublicKeyRecordV1 publicKeyRecordV1)
{
    // publicKeyRecordV1 contains the parsed DKIM public key information.
    Console.WriteLine($"DKIM Key Version: {publicKeyRecordV1.Version}");
    Console.WriteLine($"Key length in bits: {publicKeyRecordV1.KeyLength}");
    Console.WriteLine($"Revoked: {publicKeyRecordV1.IsRevoked}");
    Console.WriteLine($"Test mode: {publicKeyRecordV1.IsTestMode}");
}
else
{
    // Handle invalid DKIM public key record.
    Console.WriteLine("Invalid DKIM public key record.");
}
```


## License

This project is licensed under the MIT License. See the LICENSE file for details.
