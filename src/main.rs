use rsdsl_pppoe::client::Client;
use rsdsl_pppoe::error::{Error, Result};

use std::env;

fn main() -> Result<()> {
    let link = env::args().nth(1).ok_or(Error::MissingInterface)?;

    let clt = Client::new(&link, "alice", "1234")?;
    clt.run()?;

    Ok(())
}
