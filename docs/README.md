# Nager.EmailAuthentication

Nager.EmailAuthentication is a .NET library designed to parse and validate DMARC and DKIM easily.
With built-in support for error handling and validation, this library simplifies working with email authentication configurations.

## Features

- Parse DMARC records with comprehensive validation.
- Parse DKIM Public Key records with comprehensive validation.
- Parse DKIM Signatures with comprehensive validation.
- Parse SPF records
- Identify and report errors in DMARC configurations.
- Identify and report errors in DKIM configurations.

## Examples

**Parsing a DMARC Record**
```cs
var dmarcRecordRaw = "v=DMARC1; p=reject;";
if (!DmarcRecordParser.TryParse(dmarcRecordRaw, out var dmarcRecord))
{
}
```

**Handling Validation Errors**
```cs
var dmarcRecord = "v=DMARC1; p=invalid;";
if (!DmarcRecordDataFragmentParser.TryParse(dmarcRecord, out var dmarcDataFragment, out var parsingResults))
{
}
```

## License

This project is licensed under the MIT License. See the LICENSE file for details.
