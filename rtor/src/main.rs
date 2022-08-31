use anyhow::Result;
use arti_client::{config::TorClientConfigBuilder, TorClient};
use futures::{AsyncWriteExt, AsyncReadExt};

pub mod socks_runtime;

// fn main() {
//     println!("Hello, world!");
// }

#[tokio::main]
async fn main() -> Result<()> {

    // tracing_subscriber::fmt::init();

    {
        let r =  arti_client::config::default_config_file()?;
        eprintln!("default_config_file: [{:?}]", r);
    }


    let config = TorClientConfigBuilder::from_directories("/tmp/arti-client/state", "/tmp/arti-client/cache")
    .build()?;
    // eprintln!("config: {:?}", config);

    
    eprintln!("connecting to Tor...");


    let runtime = socks_runtime::create("127.0.0.1:7890".to_owned(), None, None)?;
    
    let tor_client = TorClient::with_runtime(runtime)
    .config(config)
    .create_bootstrapped()
    .await?;
    eprintln!("====== connected Tor with runtime");


    eprintln!("connecting to example.com...");

    // Initiate a connection over Tor to example.com, port 80.
    let mut stream = tor_client.connect(("example.com", 80)).await?;

    eprintln!("sending request...");

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await?;

    // IMPORTANT: Make sure the request was written.
    // Arti buffers data, so flushing the buffer is usually required.
    stream.flush().await?;

    eprintln!("reading response...");

    // Read and print the result.
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;

    println!("{}", String::from_utf8_lossy(&buf));

    Ok(())
}
