use rullst_connect::providers::github::GithubProvider;
use std::time::Instant;

fn main() {
    let start = Instant::now();
    for _ in 0..100 {
        let _provider = GithubProvider::new(
            "client_id".to_string(),
            "client_secret".to_string().into(),
            "http://redirect_url".to_string(),
        );
    }
    println!("Elapsed creating 100 providers: {:?}", start.elapsed());
}
