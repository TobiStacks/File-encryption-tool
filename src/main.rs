use std::{fs, io::{self, Read, Write}};
use chacha20poly1305::{
    aead::{ Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce, Key
};

pub fn encrypt(input_file: &str){
    let key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = XChaCha20Poly1305::new(&key);
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let mut file = fs::File::open(input_file).expect("\nUnable to open file\n");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).expect("\nUnable to read file\n");

    let ciphertext = cipher.encrypt(&nonce, buf.as_ref()).expect("\nEncryption failed\n");
    let mut enc_file = fs::File::create(input_file).expect("\nUnable to open file\n");

    enc_file.write_all(&ciphertext).expect("\nUnable to write data\n");
    enc_file.write_all(&nonce).expect("\nUnable to write nonce\n");
    enc_file.write_all(&key).expect("\nUnable to write key\n");

    println!("File successfully encrypted")
}

pub fn decrypt(input_file: &str) {

    let mut file = fs::File::open(input_file).expect("\nUnable to open file\n");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).expect("\nUnable to read file\n");
    
    if buf.len() < 56 {
        println!("\nInvalid encrypted file\n");
        return;
    }


    let (ciphertext, rest) = buf.split_at(buf.len() - 56);
    let (nonce_bytes, key_bytes) = rest.split_at(24);

    let key = Key::from_slice(key_bytes);
    let cipher = XChaCha20Poly1305::new(&key);
    let nonce = XNonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext).expect("\nDecryption failed\n");
    let mut dec_file = fs::File::create(input_file).expect("\nUnable to create new file\n");
    dec_file.write_all(&plaintext).expect("\nUnable to write data\n");

    println!("\nFile successfully decrypted\n");
}

fn main() {

    loop{
        println!("1 -> Encrypt File\n2 -> Decrypt\nPress q to quit\n");
        let mut input = String::new();

        io::stdin()
            .read_line(&mut input)
            .expect("\nFailed to read line\n");

        match input.trim() {
            "1" => {
                println!("\nEnter the file name: ");
                let mut file = String::new();
                
                io::stdin()
                    .read_line(&mut file)
                    .expect("\nFailed to get file\n");

                let file_path = file.trim();

                if fs::metadata(file_path).is_ok() {
                    println!("\nFile {} found\n", file_path);
                    encrypt(file_path);
                } else {
                    println!("File not found");
                }
            }
            "2" => {
                println!("\nEnter the file name: ");
                let mut file = String::new();
                
                io::stdin()
                    .read_line(&mut file)
                    .expect("\nFailed to get file\n");

                let file_path = file.trim();

                if fs::metadata(file_path).is_ok() {
                    println!("\nFile {} found\n", file_path);
                    decrypt(file_path);
                } else {
                    println!("File not found");
                }
            }
            "q" => {
                break;
            }
            _ => {
                println!("\nInvalid entry\n")
            }
        }
    }

}
