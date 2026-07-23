
> SMB Share Grepper connects to multiple SMB hosts, identifies accessible shares, and recursively searches readable files for content matching configured regular-expression patterns.


## Features

- Supports single IP addresses and CIDR ranges
- Uses multiple threads to scan hosts concurrently
- Tests effective read and write access to SMB shares
- Recursively enumerates readable files
- Searches decoded file content using specified regex patterns
- Writes matches to an output file
- Displays active processing with console loaders
- Silently skips connection, authentication, access, and decoding errors

## Target File

Create a `hosts.txt` file containing individual IP addresses or CIDR ranges:

```
10.42.1.10
10.42.1.0/24

# Comments are ignored
10.50.10.0/28
```
## Regex Patterns

Define the content to search for in the configured pattern list:

```
CREDENTIAL_PATTERNS = [
    r"(?i)password\s*[:=]\s*[^\s]+",
    r"(?i)api[_-]?key\s*[:=]\s*[^\s]+",
]
```

The tool writes the exact text returned by `regex_match.group(0)`.
## File Support

Only files that can be decoded using the encodings configured in `decode_text()` are searched.

This is best suited for text-based files such as:

- Configuration files
- Source code
- Scripts
- Logs
- JSON, XML, YAML, and INI files

Binary, compressed, encrypted, or unsupported file formats are skipped.

## Output

Matches are written to `grep_results.txt`:

```
[REGEX MATCH] \\10.42.1.20\Public\config.ini
    Line 14: db_password=ExampleValue
```

Matched content is not displayed on the console.

## Notes

The write-permission test temporarily creates and deletes a file on the remote share.

> **Use this tool only on systems you are authorised to assess.**
