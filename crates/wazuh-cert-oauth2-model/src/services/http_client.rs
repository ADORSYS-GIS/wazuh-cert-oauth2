use std::time::Duration;

#[cfg(feature = "rocket")]
use opentelemetry::global;
#[cfg(feature = "rocket")]
use opentelemetry::propagation::Injector;

use crate::models::errors::AppResult;
#[cfg(feature = "rocket")]
use opentelemetry::Context;
use reqwest::Client;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::instrument;

#[cfg(feature = "rocket")]
struct VecInjector<'a>(&'a mut Vec<(String, String)>);

#[cfg(feature = "rocket")]
impl<'a> Injector for VecInjector<'a> {
    fn set(&mut self, key: &str, value: String) {
        self.0.push((key.to_string(), value));
    }
}

#[derive(Clone)]
pub struct HttpClient {
    client: Client,
}

impl HttpClient {
    #[instrument]
    pub fn new_with_defaults() -> AppResult<Self> {
        let client = Client::builder()
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(16)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .tcp_keepalive(Duration::from_secs(60))
            .build()?;
        Ok(Self { client })
    }

    pub fn from_client(client: Client) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn fetch_json<R: DeserializeOwned>(&self, url: &str) -> AppResult<R> {
        let mut pairs = Vec::<(String, String)>::new();
        #[cfg(feature = "rocket")]
        global::get_text_map_propagator(|p| {
            p.inject_context(&Context::current(), &mut VecInjector(&mut pairs))
        });
        let mut builder = self.client.get(url);
        for (k, v) in pairs {
            builder = builder.header(k.as_str(), v);
        }
        let resp = builder.send().await?.error_for_status()?;
        Ok(resp.json().await?)
    }

    #[instrument(level = "debug", skip(self, body))]
    pub async fn post_json<B: Serialize, R: DeserializeOwned>(
        &self,
        url: &str,
        body: &B,
    ) -> AppResult<R> {
        let mut pairs = Vec::<(String, String)>::new();
        #[cfg(feature = "rocket")]
        global::get_text_map_propagator(|p| {
            p.inject_context(&Context::current(), &mut VecInjector(&mut pairs))
        });
        let mut builder = self.client.post(url).json(body);
        for (k, v) in pairs {
            builder = builder.header(k.as_str(), v);
        }
        let resp = builder.send().await?.error_for_status()?;
        Ok(resp.json().await?)
    }

    #[instrument(level = "debug", skip(self, token, body))]
    pub async fn post_json_auth<B: Serialize, R: DeserializeOwned>(
        &self,
        url: &str,
        token: &str,
        body: &B,
    ) -> AppResult<R> {
        let mut pairs = Vec::<(String, String)>::new();
        #[cfg(feature = "rocket")]
        global::get_text_map_propagator(|p| {
            p.inject_context(&Context::current(), &mut VecInjector(&mut pairs))
        });
        let mut builder = self.client.post(url).bearer_auth(token).json(body);
        for (k, v) in pairs {
            builder = builder.header(k.as_str(), v);
        }
        let resp = builder.send().await?.error_for_status()?;
        Ok(resp.json().await?)
    }
}
