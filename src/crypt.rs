use std::thread;
use std::sync::{Arc,mpsc};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_A() {
        assert_eq!(super::decode_hexbyte(0x41).unwrap(), 0xa);
    }

    #[test]
    fn decode_badbyte() {
        let result = match super::decode_hexbyte(0x12) {
            Ok(val) => val,
            Err(_)  => 100,
        };
        assert_eq!(result, 100);
    }

    #[test]
    fn decode_AAAA() {
        let bytes = String::from("41414141");
        let msg = String::from("AAAA");
        let decoded = super::decode_hexbytes(&bytes.into_bytes()).unwrap();
        assert_eq!(decoded, msg.into_bytes());
    }

    #[test] 
    fn decode_adele() {
        let bytes = String::from("546869732069732074686520656e642c20686f6c6420796f75722062726561746820616e6420636f756e7420746f2031302e");
        let msg = String::from("This is the end, hold your breath and count to 10.");
        let decoded = super::decode_hexbytes(&bytes.into_bytes()).unwrap();
        assert_eq!(decoded, msg.into_bytes());
    }
}

/// Decodes a hexadecimal representation of a string
/// TODO implement better error handling
pub fn decode_hexbytes(hexbytes: &Vec<u8>) -> Result<Vec<u8>, &'static str> {

    let hex_values: Vec<u8> = hexbytes.iter()
                        .map(|&x| decode_hexbyte(x).unwrap())
                        .collect();
    let mut bytes: Vec<u8> = Vec::new();
    for i in (0..hex_values.len() - 1).filter(|&x| x % 2 == 0) {
        bytes.push((hex_values[i] * 0x10) + hex_values[i+1]);
    }
    Ok(bytes)
}

/// Converts a given hexadecimal character into the corresponding integer value
pub fn decode_hexbyte(byte: u8) -> Result<u8, &'static str> {

    match byte {
        0x30 ... 0x3a     => Ok(byte - 0x30),
        0x41 ... 0x46     => Ok(byte - 0x41 + 0xa),
        0x61 ... 0x66     => Ok(byte - 0x61 + 0xa),
        0x0d              => Ok(0),     // TODO may want to end parsing here
        _                 => Err("Not a valid hexadecimal digit."),
    }
}

/// Scores the text on its similarity to English using frequency analysis
pub fn score_text(text: Vec<u8>) -> i32 {

    let mut score: i32 = 0;
    for &c in text.iter() {
        match c {
            0x65            => score += 20, // e
            0x74            => score += 20, // t
            0x61            => score += 20, // a
            0x6f            => score += 20, // o
            0x69            => score += 20, // i
            0x6e            => score += 20, // n
            0x61 ... 0x7a   => score += 10,
            0x20            => score += 0,
            _               => score -= 10,
        }
    }
    return score / (text.len() as i32);
}

/// Encrypts a message by XORing each byte with a given character
pub fn single_key_xor(plaintext: &Vec<u8>, key: u8) -> Vec<u8> {

    plaintext.iter().map(|b| b ^ key).collect()
}

/// Decrypts ciphertext that has been XORed against a single byte
pub fn break_single_xor(ciphertext: Vec<u8>) {

    let mut best_score = 0;
    let mut key_guess: u8 = 0;
    for c in 0..255 {
        let decoded_text = single_key_xor(&ciphertext, c);
        let score_guess = score_text(decoded_text);
        if score_guess > best_score {
            best_score = score_guess;
            key_guess = c;
        }
    }
    
    println!("Final key: 0x{} ({})", key_guess, key_guess as char);
}

/// Uses multiple threads to decrypt ciphertext XORed against single byte
pub fn break_single_xor_threaded(ciphertext: Vec<u8>) {

    let ciphertext = Arc::new(ciphertext);
    let (tx, rx) = mpsc::channel();
    
    // spawn threads
    for i in 0..2 {

        let (ciphertext, tx) = (ciphertext.clone(), tx.clone());
        
        thread::spawn(move || {
            let min = 128*i;
            let max = min + 127;
            let mut best_score = 0;
            let mut key_guess: u8 = 0;
            for c in min..max {
                let decoded_text = single_key_xor(&ciphertext, c);
                let score_guess = score_text(decoded_text);
                if score_guess > best_score {
                    best_score = score_guess;
                    key_guess = c;
                }
            }
            tx.send((best_score, key_guess)).unwrap();
        });
    }    

    // collect results, determine best score and probable key
    let mut best_score = 0;
    let mut key: u8 = 0;
    for _ in 0..2 {
        let (score_guess, key_guess) = rx.recv().unwrap();
        if score_guess > best_score {
            best_score = score_guess;
            key = key_guess;
        }
    }
    println!("Final key: 0x{} ({})", key, key as char);
}
