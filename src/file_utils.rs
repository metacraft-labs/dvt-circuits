use serde::de::DeserializeOwned;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;

fn check_if_file_exists(path: &str) -> Result<(), Box<dyn Error>> {
    if !Path::new(path).exists() {
        return Err(format!("File '{}' does not exist.", path).into());
    }
    Ok(())
}

pub fn read_text_file(filename: &str) -> Result<String, Box<dyn Error>> {
    check_if_file_exists(filename)?;
    let mut file =
        File::open(filename).map_err(|e| format!("Error opening file {filename}: {e}"))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| format!("Error reading file {filename}: {e}"))?;
    Ok(contents)
}

pub fn read_data_from_json_file<T>(filename: &str) -> Result<T, Box<dyn Error>>
where
    T: DeserializeOwned,
{
    let contents = read_text_file(filename)?;
    let data: T = serde_json::from_str(&contents)
        .map_err(|e| format!("Error parsing JSON in {filename}: {e}"))?;
    Ok(data)
}
