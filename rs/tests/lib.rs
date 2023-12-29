#[cfg(test)]
mod tests {
    use std::process::{Command, Output};
    use rand::{distributions::Alphanumeric, Rng};
    use keypair::{sk, vk, sign};

    fn rand_string(len: usize) -> String {
        let rng = rand::thread_rng();
        rng.sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
    }

    #[test]
    fn test_js_sign_rt_verify() {

        // js generates signing key
        let mut output: Output = Command::new("node")
            .arg("../js/index.mjs") 
            .arg("sk")            
            .output()
            .expect("failed to execute process");        
        let sk: String = String::from_utf8_lossy(&output.stdout).into_owned().trim().to_string();
        println!("[rs] len={} sk={}", &sk.len(), &sk);
        
        // js generates verifying key
        output = Command::new("node")
        .arg("../js/index.mjs") 
        .arg("vk")            
        .arg(&sk)
        .output()
        .expect("failed to execute process");
        let vk: String = String::from_utf8_lossy(&output.stdout).into_owned().trim().to_string();
        println!("[rs] len={} vk={}", &vk.len(), &vk);

        // generates random message
        let message: String = rand_string(20);       

        // js sign
        output = Command::new("node")
        .arg("../js/index.mjs") 
        .arg("sign")            
        .arg(&message)
        .arg(&sk)
        .output()
        .expect("failed to execute process");
        let signature: String = String::from_utf8_lossy(&output.stdout).into_owned().trim().to_string();
        println!("[rs] len={} signature={}", &signature.len(), &signature);

        // rs verify
        output = Command::new("node")
        .arg("../js/index.mjs") 
        .arg("verify")    
        .arg(&signature)      
        .arg(&message)
        .arg(&vk)
        .output()
        .expect("failed to execute process");
        let res: String = String::from_utf8_lossy(&output.stdout).into_owned().trim().to_string();
        println!("[rs] len={} res={}", &res.len(), &res);

        // assert result
        assert_eq!("true", res);
    }

    #[test]
    fn test_rt_sign_js_verify() {

        // rt generates signing key
        let sk_bytes: [u8; 32] = sk();
        let sk: String = bytes_to_hex(&sk_bytes);
        println!("[rs] len={} sk_str={}", &sk.len(), &sk);
        
        // rt generates verifying key
        let vk_bytes: [u8; 32] = vk(sk_bytes);
        let vk: String = bytes_to_hex(&vk_bytes);
        println!("[rs] len={} vk={}", &vk.len(), &vk);

        // generates random message
        let message: String = rand_string(20);       

        // rt sign
        let signature_bytes: [u8; 64] = sign(sk_bytes, message.as_bytes());
        let signature: String = bytes_to_hex(&signature_bytes);
        println!("[rs] len={} signature={}", &signature.len(), &signature);

        // js verify
        let output: Output = Command::new("node")
        .arg("../js/index.mjs") 
        .arg("verify")    
        .arg(&signature)      
        .arg(&message)
        .arg(&vk)
        .output()
        .expect("failed to execute process");
        let res: String = String::from_utf8_lossy(&output.stdout).into_owned().trim().to_string();
        println!("[rs] len={} res={}", &res.len(), &res);

        // assert result
        assert_eq!("true", res);
    }
}