use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug, Serialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SimpleUserRepresentation {
    pub id: Option<String>,
    pub enabled: bool,
    pub username: Option<String>,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}
