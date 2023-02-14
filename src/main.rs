
fn main(){

}



#[cfg(test)]
mod test{

    #[test]
    pub fn generate() {
        use wallet_rust::bips::bip39::{Mnemonic, MnemonicType};
        use wallet_rust::bips::wordlists::Language;
        use wallet_rust::bips::bip32::ExtendedKey;
        use wallet_rust::bips::DerivationPath;
        
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        println!("{}",mnemonic);
        let seed = mnemonic.to_seed("password");
        let master_key = ExtendedKey::new_master(&seed).unwrap();
        
        // define the path to derive, We will use ethereum path
        let path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        let child_key = master_key.derive_path(&path).unwrap();
        let private_key = child_key.private_key();
        let public_key = private_key.public_key();
        let address = public_key.address();
        println!("{}",address)
    }

}
