use anyhow::Result;
use rig::client::ProviderClient;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub enum LlmProvider {
    OpenAi,
    Anthropic,
    Gemini,
    Ollama,
}

impl FromStr for LlmProvider {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "openai" => Ok(LlmProvider::OpenAi),
            "anthropic" => Ok(LlmProvider::Anthropic),
            "gemini" => Ok(LlmProvider::Gemini),
            "ollama" => Ok(LlmProvider::Ollama),
            _ => anyhow::bail!("Unknown LLM provider: {}", s),
        }
    }
}

pub enum LlmClient {
    OpenAi(rig::providers::openai::Client),
    Anthropic(rig::providers::anthropic::Client),
    Gemini(rig::providers::gemini::Client),
}

pub fn create_provider(provider: &LlmProvider) -> Result<LlmClient> {
    match provider {
        LlmProvider::OpenAi => {
            let client = rig::providers::openai::Client::from_env();
            Ok(LlmClient::OpenAi(client))
        }
        LlmProvider::Anthropic => {
            let client = rig::providers::anthropic::Client::from_env();
            Ok(LlmClient::Anthropic(client))
        }
        LlmProvider::Gemini => {
            let client = rig::providers::gemini::Client::from_env();
            Ok(LlmClient::Gemini(client))
        }
        LlmProvider::Ollama => {
            anyhow::bail!("Ollama support not yet implemented")
        }
    }
}
