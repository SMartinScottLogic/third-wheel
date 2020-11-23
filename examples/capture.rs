use async_trait::async_trait;
use std::fs::File;
use std::io::prelude::*;

use argh::FromArgs;
use http::{Request, Response};

use third_wheel::*;

/// Run a TLS mitm proxy that does no modification to the traffic
#[derive(FromArgs)]
struct StartMitm {
    /// port to bind proxy to
    #[argh(option, short = 'p', default = "8080")]
    port: u16,

    /// pem file for self-signed certificate authority certificate
    #[argh(option, short = 'c', default = "\"ca/ca_certs/cert.pem\".to_string()")]
    cert_file: String,

    /// pem file for private signing key for the certificate authority
    #[argh(option, short = 'k', default = "\"ca/ca_certs/key.pem\".to_string()")]
    key_file: String,
}

struct EmptyCapturer;

#[async_trait]
impl MitmLayer for EmptyCapturer {
    async fn capture_request(&self, r: &Request<Vec<u8>>) -> RequestCapture {
        println!("capture_request: {:?}", r);
        RequestCapture::Continue
    }
    async fn capture_response(
        &self,
        request: &Request<Vec<u8>>,
        response: &Response<Vec<u8>>,
    ) -> ResponseCapture {
        let path = String::from("archive/") + request.headers()[http::header::HOST].to_str().unwrap_or(".") + "/" + request.uri().path();
        let path = std::path::Path::new(&path);
        let file_name = path.file_name().map(|v| v.to_str().unwrap()).unwrap_or("").to_string().chars().collect::<Vec<char>>().chunks(128).map(|c| c.iter().collect::<String>()).collect::<Vec<String>>();
        let path_buf = file_name.into_iter().fold(path.parent().unwrap().to_path_buf(), |pb, x| pb.join(x));
        let path = path_buf.as_path();
        println!("{:?}", path);
        std::fs::create_dir_all(path.parent().unwrap());
        println!("{} exists: {}", path.display(), path.exists());
                match File::create(path) {
                    Ok(mut file) => file.write_all(response.body()),
                    Err(e) => {println!("Failed to open '{:?}': {:?}", path, e); Ok(())}
                };
        println!("capture_response: {:?}", response);
        ResponseCapture::Continue
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: StartMitm = argh::from_env();
    let ca = CertificateAuthority::load_from_pem_files(&args.cert_file, &args.key_file)?;
    start_mitm(args.port, wrap_mitm_in_arc!(EmptyCapturer {}), ca).await
}
