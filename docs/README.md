# Nager.EmailAuthentication

Nager.EmailAuthentication is a .NET library designed to parse and validate DMARC and DKIM easily.
With built-in support for error handling and validation, this library simplifies working with email authentication configurations.

## Features

- Parse DMARC records according to RFC 9989 (DMARCbis), including the tags `np`, `psd` and `t`.
- Parse DKIM Public Key records with comprehensive validation, including the key length.
- Parse DKIM Signatures with comprehensive validation.
- Parse SPF records into mechanisms and modifiers.
- Identify and report errors in DMARC, DKIM and SPF configurations.

## Examples

**Parsing a DMARC Record**
```cs
var dmarcRecordRaw = "v=DMARC1; p=reject;";
if (DmarcRecordParser.TryParse(dmarcRecordRaw, out var dmarcRecord))
{
}
```

**Handling Validation Errors**
```cs
var dmarcRecordRaw = "v=DMARC1; p=reject; pct=50; adkim=x;";
if (DmarcRecordParser.TryParse(dmarcRecordRaw, out var dmarcRecord, out var parsingResults))
{
    // parsingResults contains a warning for the obsolete tag pct and an error for adkim
}
```

**Parsing an SPF Record**
```cs
var spfRecordRaw = "v=spf1 include:spf.example.com -all";
if (SpfRecordDataFragmentParserV1.TryParse(spfRecordRaw, out var spfRecord, out var parsingResults))
{
}
```

## License

This project is licensed under the MIT License. See the LICENSE file for details.
