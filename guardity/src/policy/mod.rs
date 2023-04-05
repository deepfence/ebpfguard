use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicySubject {
    #[serde(rename = "process")]
    Process(PathBuf),
    #[serde(rename = "container")]
    Container(String),
    #[serde(rename = "all")]
    All,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Policy {
    #[serde(rename = "setuid")]
    SetUid { subject: PolicySubject, allow: bool },
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_policy() {
        let yaml = "
- !setuid
  subject: all  
  allow: false
- !setuid
  subject: !process /usr/bin/sudo
  allow: true
- !setuid
  subject: !container deepfenceio/deepfence_agent_ce
  allow: true
";
        let policy = serde_yaml::from_str::<Vec<Policy>>(yaml).unwrap();
        assert_eq!(policy.len(), 3);
        assert_eq!(
            policy[0],
            Policy::SetUid {
                subject: PolicySubject::All,
                allow: false
            }
        );
        assert_eq!(
            policy[1],
            Policy::SetUid {
                subject: PolicySubject::Process(PathBuf::from("/usr/bin/sudo")),
                allow: true
            }
        );
        assert_eq!(
            policy[2],
            Policy::SetUid {
                subject: PolicySubject::Container("deepfenceio/deepfence_agent_ce".to_string()),
                allow: true
            }
        );
    }
}
