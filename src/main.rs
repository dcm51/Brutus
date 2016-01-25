extern crate rustc_serialize;
extern crate docopt;

use std::error::Error;
use std::fs::File;
use std::path::Path;
use std::io::prelude::*;
use docopt::Docopt;

mod crypt;

static USAGE: &'static str = "
USAGE: brutus [options] <file>

Options: 
    -s, --single    Use a single-threaded cracker (default)
    -t, --threaded  Use a multi-threaded cracker
";

#[derive(RustcDecodable, Show)]
struct Args {
    arg_file: String,
    flag_single: bool,
    flag_threaded: bool,
}

fn main() {

    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.decode())
        .unwrap_or_else(|e| e.exit());

    // read data from file into memory
    let path = Path::new(&args.arg_file);
    let mut buf: Vec<u8> = vec![];
    let mut file = match File::open(&path) {
        Err(why)    => panic!("Error when opening {}: {}",
                              path.display(),
                              Error::description(&why)),
        Ok(file)    => file,
    };
    file.read_to_end(&mut buf)
        .ok()
        .expect("Failed to read data into memory.");
    
    // parse data and decrypt
    let ciphertext = crypt::decode_hexbytes(&buf);
    if args.flag_threaded {
        crypt::break_single_xor_threaded(ciphertext.unwrap());
    } else {
        crypt::break_single_xor(ciphertext.unwrap());
    }        
}
