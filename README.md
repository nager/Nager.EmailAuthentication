# Nager.EmailAuthentication

Nager.EmailAuthentication is a .NET library designed to parse and validate DMARC records easily.
With built-in support for error handling and validation, this library simplifies working with email authentication configurations.

## Features

- Parse DMARC records with comprehensive validation.
- Identify and report errors in DMARC configurations.

## Installation

The package is available on [nuget](https://www.nuget.org/packages/Nager.EmailAuthentication)
```
PM> install-package Nager.EmailAuthentication
```

or

```
dotnet add package Nager.EmailAuthentication
```

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
