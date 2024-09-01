<h1>
  Vanish
  <a href="https://github.com/shubhexists/vanish/actions"><img src="https://img.shields.io/github/actions/workflow/status/shubhexists/vanish/rust.yml?branch=master&label=workflow" alt="GitHub Actions workflow status" /></a>
</h1>

Fast and simple tool to generate development certificates locally, built in Rust. 

Vanish follows the <b>X.509 Standards</b> as mentioned in [RFC 3280](https://www.ietf.org/rfc/rfc3280.txt) ( April 2002 ) to match the PKI Standards.

Vanish also follow the [XDG Base Direcctory Specification](https://specifications.freedesktop.org/basedir-spec/latest/) to store the CA Keys.

```sh
// To generate certificates
$ vanish generate -d localhost -d www.vedanalytics.in

// to generate certificate requests
$ vanish generate -d localhost --req-only
```
## About
Generating certificates locally might be the best option rather that generating it from a registered Authority as you have the control of your private key.

Vanish's CLI built in Rust allows you to generate trusted certificates for your domains which you can use for any domain ( even `localhost` !! ). 
Apart from that, many measures have been taken, keeping performance in mind. Vanish -
- Is Cross-platform (macOS, Windows, Linux)
- is a Single binary, hence easy installation
- Built with speed in mind 
- Small Binary Size ( Less than 4 MBs on Debian )

## Installation
Currently Vanish is just distributed through [Cargo](https://crates.io/crates/vanish) 
but we are working full time to support distribution from other package managers.

### Cargo 
```sh
cargo install vanish
```

### Build From Source 
```sh
# Install Rust
git clone https://github.com/shubhexists/vanish
cd vanish
cargo build --release
```

## Work In Progress
Although Vanish is now functional, it is to be considered that it is still a new project and hence many planned features are yet to be implemented. 
Vanish has implemented - 

- [x] - Generate Certificate Requests
- [x] - Generate Certificates and Keys for multiple Domains
- [ ] - Add Trust Store Support for multiple Platforms
- [ ] - Add more encoding Formats ( Currently, only `.pem` is supported.)
- [ ] - Add Support for multiple CA's in the Root Store
- [ ] - Add S/MIME support for emails
- [ ] - Modify Key Size ( Currently it is 2048 bytes ). See, []

These are just the planned ones, It may have many other features. If you have one, file it in the issues !

## Paramenters 
The Vanish CLI has many parameters to help you generate certificates without much hassle! 
 > Note - Order of these commands don't matter. So, you can place them in any order.

Let's have a look at them - 

1) `-d` or `--domain` to add a domain to the list
```
vanish generate -d vedanalytics.in -d localhost
```
2) `--no-ca` to force Vanish to use the default CA in the Data Directory. If it could not find a certificate, it will return a error :D
```
vanish generate -d vedanalytics.in -d localhost --no-ca
```
3) `--req-only` to generate a "Certificate Request" rather than a Certificate. You can use this Request to further generate a Certificate.
```
vanish generate -d vedanalytics.in -d localhost --req-only
```
4) `--keyfile` and `--certfile` to provide your own CA certificates. Vanish would then use these certificates to generate your Ceertificate!

   > Note: You need to provide both `--keyfile` and `--certfile`. If you provide just one, Vanish will prompt you a error!
```
vanish generate -d vedanalytics.in -d localhost --keyfile ./ca-key.pem --certfile ./ca.pem
```
5) `--csr` to generate certificates from a "Certificate Request" file

   > Note - `--csr` flag conflicts with the `--req-only` flag as you can not generate Requests from a Request right? : D
```
vanish generate --csr ./csr.pem
```
6) `-o` or `--output` to specify a output directory. 

   > Note: The value of `-o` Argument should be a directory and not a file. Vanish automatically generates the filename to store in the specified directory
   > If you don't specify a directory, the default directories will be the Current Working Directory.
```
vanish generate --csr ./csr.pem -o ./certificates/
```
7) `-c` for Country, `-cn` for `Common Name`, `-s` for State. However option, it is a good practice to include these things in your certificate.
```
vanish generate -d vedanalytics.in -d localhost --no-ca -c India -s Delhi
```
## NOTE

Thank's for reading. Do drop a star ✨ as it helps to spread the words :D 
