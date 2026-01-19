use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "extanalyzer")]
#[command(about = "Analyze Chrome and Firefox browser extensions")]
struct Args {
    /// Extension ID, URL, or file path
    #[arg(required_unless_present = "batch")]
    input: Option<String>,

    /// Analyze Firefox extension (default is Chrome)
    #[arg(long)]
    firefox: bool,

    /// Batch file with extension IDs/URLs
    #[arg(long)]
    batch: Option<String>,

    /// LLM provider (openai, anthropic, gemini, ollama)
    #[arg(long, default_value = "openai")]
    llm: String,

    /// Skip LLM analysis
    #[arg(long)]
    no_llm: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    println!("extanalyzer v{}", env!("CARGO_PKG_VERSION"));
    println!("Args: {:?}", args);
    Ok(())
}
