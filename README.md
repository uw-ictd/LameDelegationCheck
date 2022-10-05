# Lame Delegation Checker

A simple tool to identify lame delegations in DNS.

### Build

```shell
make
```

### Running

```shell
./lame-delegation-check query --domain <domain_name> --queryType <dns_query_type>
```

Scanning a set of entries, the input file is a list of hostnames with one entry per line.

```shell
./lame-delegation-check scan --input <input_file.txt> --outdir <output_directory_to_store_results> --queryType <A|AAAA|MX|etc..,>
```

This creates a `csv` file in the `outdir` directory and creates the directory if it does not already exist.
