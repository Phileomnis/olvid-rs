#[cfg(test)]
pub mod tests {
    use std::fs;

    use serde::{de::DeserializeOwned, Deserialize, Deserializer};
    use serde_json::Number;

    #[derive(Clone, Debug)]
    pub struct TestBigInteger(pub String);

    impl<'de> Deserialize<'de> for TestBigInteger {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = Number::deserialize(deserializer)?;
            Ok(TestBigInteger(s.to_string()))
        }
    }

    pub fn get_test_vectors<T: DeserializeOwned>(file_name : &str) -> Vec<T> {
        // let file_path = concat!(env!("CARGO_MANIFEST_DIR"), "/resources/test/", "TestVectorsPRNGGenBigInt.json");
        let mut file_path = String::from(env!("CARGO_MANIFEST_DIR"));
        file_path.push_str("/resources/test/");
        file_path.push_str(file_name);

        let file_content = fs::read_to_string(file_path.clone()).expect(&format!("Couldn't load {}", file_path));
        serde_json::from_str(&file_content).expect("Couldn't parse JSON")
    }
}
