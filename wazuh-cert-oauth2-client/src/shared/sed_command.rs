use anyhow::Result;
use std::process::ExitStatus;
use tokio::{process::Command};
use std::fs::{self, OpenOptions};
use quick_xml::events::{Event, BytesStart, BytesText};
use quick_xml::Reader;
use quick_xml::Writer;
use std::io::{BufReader};
use std::os::unix::process::ExitStatusExt;

/// Run a sed command to replace the content of a file.
pub async fn sed_command(content: &str, file_path: &str, agent_name: &str) -> Result<ExitStatus> {
    let status = if cfg!(target_os = "macos") {
        Command::new("sed")
            .arg("-i").arg("")
            .arg(&content)
            .arg(&file_path)
            .status()
            .await?
    } else if cfg!(target_os = "linux") {
        Command::new("sed")
            .arg("-i")
            .arg(&content)
            .arg(&file_path)
            .status()
            .await?
    } else {
        // Handle the case for Windows or other OSs
        let input_file = fs::File::open(file_path)?;
        let buf_reader = BufReader::new(input_file);
        let mut reader = Reader::from_reader(buf_reader);
        reader.trim_text(true);

        let output_file = OpenOptions::new().write(true).truncate(true).open(file_path)?;
        let mut writer = Writer::new(output_file);

        let mut buf = Vec::new();
        let mut in_agent_name = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    if e.name() == quick_xml::name::QName(b"agent_name") {
                        in_agent_name = true;
                        writer.write_event(Event::Start(e.clone()))?;
                    } else {
                        writer.write_event(Event::Start(e))?;
                    }
                }
                Ok(Event::Text(e)) => {
                    if in_agent_name {
                        writer.write_event(Event::Text(BytesText::new(agent_name)))?;
                    } else {
                        writer.write_event(Event::Text(e))?;
                    }
                }
                Ok(Event::End(e)) => {
                    if e.name() == quick_xml::name::QName(b"agent_name") {
                        in_agent_name = false;
                        writer.write_event(Event::End(e.clone()))?;
                    } else {
                        writer.write_event(Event::End(e))?;
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => panic!("Error at position {}: {:?}", reader.buffer_position(), e),
                _ => (),
            }
            buf.clear();
        }
        
        // Return a dummy ExitStatus, as no system command is run for this block
        ExitStatus::from_raw(0).into()
    };

    Ok(status)
}
