# Nager.EmailAuthentication

Nager.EmailAuthentication is a .NET library for parsing DMARC, DKIM, and SPF records into structured, easy-to-use data.

- **DMARC** (Domain-based Message Authentication, Reporting, and Conformance) enables domain owners to specify how mail receivers should handle emails that fail authentication.
- **DKIM** (DomainKeys Identified Mail) adds a cryptographic signature to outgoing emails to ensure their authenticity and integrity.
- **SPF** (Sender Policy Framework) specifies which IP addresses are allowed to send email on behalf of a domain.

This library focuses on extracting and interpreting the content of these DNS records, enabling applications to analyze and work with email authentication settings programmatically.

## Features

- Parse DMARC records with comprehensive validation.
- Parse DKIM Public Key records with comprehensive validation.
- Parse DKIM Signatures with comprehensive validation.
- Identify and report errors in DMARC configurations.
- Identify and report errors in DKIM configurations.

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

Use `DmarcRecordParser.TryParse` to validate a DMARC record string. The method returns `true` if parsing succeeds and outputs a `DmarcRecord` object.

```cs
var dmarcRecordRaw = "v=DMARC1; p=reject;";
if (!DmarcRecordParser.TryParse(dmarcRecordRaw, out var dmarcRecord))
{
    // dmarcRecord now contains the parsed DMARC policy.
    Console.WriteLine($"DMARC policy: {dmarcRecord.Policy}");
}
else
{
    // Handle unexpected parsing failure (should not happen for a valid record).
}
```

### Handling DMARC Validation Errors

To capture validation errors (e.g., missing or invalid tags), use `DmarcRecordDataFragmentParser.TryParse`, which provides detailed parsing results when the record is invalid:

```cs
var dmarcRecord = "v=DMARC1; p=invalid;";
if (!DmarcRecordDataFragmentParser.TryParse(dmarcRecord, out var dmarcDataFragment, out var parsingResults))
{
    // parseResult contains error messages explaining what went wrong.
    Console.WriteLine("DMARC parsing failed:");
    foreach (var error in parseResult.Errors)
    {
        Console.WriteLine($"  - {error}");
    }
}
```

### Parsing a DKIM Public Key Record

Similarly, you can parse a DKIM public key (DNS TXT) record. Use `DkimPublicKeyRecordParser.TryParse` and check for errors:

```cs
string dkimKeyRecord = "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ..."; // Example public key
if (DkimPublicKeyRecordParser.TryParse(dkimKeyRecord, out var publicKeyRecord))
{
    // publicKeyRecord contains the parsed DKIM public key information.
    Console.WriteLine($"DKIM Key Version: {publicKeyRecord.Version}");
}
else
{
    // Handle invalid DKIM public key record.
    Console.WriteLine("Invalid DKIM public key record.");
}
```


## License

This project is licensed under the MIT License. See the LICENSE file for details.
