# steghunt
 This script automates looking for stegfiles hidden by [steghide](https://www.kali.org/tools/steghide/) in a large collection of media files using [stegseek](https://github.com/RickdeJager/stegseek).
 
 Use `steghunt --help` to get the full list of available options:
```
USAGE:
    steghunt [OPTIONS] --input <IN_PATH> --output <OUT_PATH> <MODE>

ARGS:
    <MODE>    Mode to use [possible values: seed, crack, seedcrack]

OPTIONS:
    -i, --input <IN_PATH>             Path to the directory containing the images that will be
                                      processed
    -o, --output <OUT_PATH>           Path to the directory where cracked files will be stored (does
                                      not need to exist)
    -r, --recursive                   Recursively search subdirectories
    -d, --dupeskip                    Skip duplicate images
    -m, --minsize <MIN_SIZE>          Skip images below this size in Bytes [default: 1024]
    -w, --wordlist <WORDLIST_PATH>    Path to the wordlist to use for cracking
    -q, --quiet                       Don't print stats
    -h, --help                        Print help information
    -V, --version                     Print version information
```

