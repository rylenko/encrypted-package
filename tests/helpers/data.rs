#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Data(pub String);

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PublicData(pub u8);
