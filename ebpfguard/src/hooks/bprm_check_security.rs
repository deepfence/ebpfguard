use aya::{
    maps::{AsyncPerfEventArray, MapData},
    programs::lsm::LsmLink,
};
use ebpfguard_common::alerts as ebpf_alerts;
use tokio::sync::mpsc::Receiver;

use crate::{alerts, error::EbpfguardError};

use super::perf_array_alerts;

pub struct BprmCheckSecurity {
    #[allow(dead_code)]
    pub(crate) program_link: Option<LsmLink>,
    pub(crate) perf_array: AsyncPerfEventArray<MapData>,
}

impl BprmCheckSecurity {
    pub async fn alerts(&mut self) -> Result<Receiver<alerts::BprmCheckSecurity>, EbpfguardError> {
        perf_array_alerts::<ebpf_alerts::BprmCheckSecurity, alerts::BprmCheckSecurity>(
            &mut self.perf_array,
        )
        .await
    }
}
