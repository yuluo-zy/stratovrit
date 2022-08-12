// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
//
// StratoVirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use super::errors::{ErrorKind, Result};

use error_chain::bail;

use crate::config::{CmdParser, ConfigCheck, MAX_STRING_LENGTH};

/// XHCI contoller configuration.
pub struct XhciConfig {
    pub id: String,
}

impl XhciConfig {
    fn new() -> Self {
        XhciConfig { id: String::new() }
    }
}

impl ConfigCheck for XhciConfig {
    fn check(&self) -> Result<()> {
        if self.id.len() > MAX_STRING_LENGTH {
            return Err(ErrorKind::StringLengthTooLong("id".to_string(), MAX_STRING_LENGTH).into());
        }
        Ok(())
    }
}

pub fn parse_xhci(conf: &str) -> Result<XhciConfig> {
    let mut cmd_parser = CmdParser::new("nec-usb-xhci");
    cmd_parser.push("").push("id").push("bus").push("addr");
    cmd_parser.parse(conf)?;
    let mut dev = XhciConfig::new();
    if let Some(id) = cmd_parser.get_value::<String>("id")? {
        dev.id = id;
    } else {
        bail!("id is none for usb xhci");
    }
    dev.check()?;
    Ok(dev)
}
