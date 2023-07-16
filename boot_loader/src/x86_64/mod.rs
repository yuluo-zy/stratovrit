// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
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
// 引导加载器，用于加载PE和bzImage格式的Linux内核映像到虚拟机的内存中。该引导加载器遵循x86 boot protocol。
//! Boot Loader load PE and bzImage linux kernel image to guest memory according
//! [`x86 boot protocol`](https://www.kernel.org/doc/Documentation/x86/boot.txt).
//!
//! Below is x86_64 bootloader memory layout:
//!
//! ``` text
//!                 +------------------------+
//!   0x0000_0000   |  Real Mode IVT         |
//!                 |                        |
//!                 +------------------------+
//!   0x0000_7000   |                        |
//!                 |  Zero Page             |
//!                 |                        |
//!   0x0000_9000   +------------------------+
//!                 |  Page Map Level4       |
//!                 |                        |
//!   0x0000_a000   +------------------------+
//!                 |  Page Directory Pointer|
//!                 |                        |
//!   0x0000_b000   +------------------------+
//!                 |  Page Directory Entry  |
//!                 |                        |
//!   0x0002_0000   +------------------------+
//!                 |  Kernel Cmdline        |
//!                 |                        |
//!   0x0009_fc00   +------------------------+
//!                 |  EBDA - MPtable        |
//!                 |                        |
//!   0x000a_0000   +------------------------+
//!                 |  VGA_RAM               |
//!                 |                        |
//!   0x000f_0000   +------------------------+
//!                 |  MB_BIOS               |
//!                 |                        |
//!   0x0010_0000   +------------------------+
//!                 |  Kernel _setup         |
//!                 |                        |
//!                 ~------------------------~
//!                 |  Initrd Ram            |
//!   0x****_****   +------------------------+
//! ```

mod bootparam;
mod direct_boot;
mod standard_boot;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use kvm_bindings::kvm_segment;

use address_space::AddressSpace;
use devices::legacy::FwCfgOps;

const ZERO_PAGE_START: u64 = 0x0000_7000;
const PML4_START: u64 = 0x0000_9000;
const PDPTE_START: u64 = 0x0000_a000;
const PDE_START: u64 = 0x0000_b000;
const SETUP_START: u64 = 0x0001_0000;
const CMDLINE_START: u64 = 0x0002_0000;
const BOOT_HDR_START: u64 = 0x0000_01F1;
const BZIMAGE_BOOT_OFFSET: u64 = 0x0200;

const EBDA_START: u64 = 0x0009_fc00;
const VGA_RAM_BEGIN: u64 = 0x000a_0000;
const MB_BIOS_BEGIN: u64 = 0x000f_0000;
pub const VMLINUX_RAM_START: u64 = 0x0010_0000;
const INITRD_ADDR_MAX: u64 = 0x37ff_ffff;

const VMLINUX_STARTUP: u64 = 0x0100_0000;
const BOOT_LOADER_SP: u64 = 0x0000_8ff0;

const GDT_ENTRY_BOOT_CS: u8 = 2;
const GDT_ENTRY_BOOT_DS: u8 = 3;
const BOOT_GDT_OFFSET: u64 = 0x500;
const BOOT_IDT_OFFSET: u64 = 0x520;

const BOOT_GDT_MAX: usize = 4;

const REAL_MODE_IVT_BEGIN: u64 = 0x0000_0000;

/// Boot loader config used for x86_64.
pub struct X86BootLoaderConfig {
    /// Path of the kernel image.
    pub kernel: Option<std::path::PathBuf>,
    /// Path of the initrd image.
    pub initrd: Option<PathBuf>,
    /// Kernel cmdline parameters.
    pub kernel_cmdline: String,
    /// VM's CPU count.
    pub cpu_count: u8,
    /// (gap start, gap size)
    pub gap_range: (u64, u64),
    /// IO APIC base address
    pub ioapic_addr: u32,
    /// Local APIC base address
    pub lapic_addr: u32,
    /// Range of identity-map and TSS
    pub ident_tss_range: Option<(u64, u64)>,
    /// Boot from 64-bit protection mode or not.
    pub prot64_mode: bool,
}

// 这段代码是使用Rust语言定义的两个结构体：`X86BootLoader`和`BootGdtSegment`。这些结构体用于描述x86_64架构的引导加载程序（bootloader）在客户机内存中的起始地址和相关信息。
//
// 1. `X86BootLoader`结构体：
// - `boot_ip`：引导加载程序的指令指针（Instruction Pointer），表示引导加载程序的代码执行的起始地址。
// - `boot_sp`：引导加载程序的堆栈指针（Stack Pointer），表示引导加载程序的栈的起始地址。
// - `boot_selector`：引导加载程序的代码段选择子（Code Segment Selector），用于选择GDT（Global Descriptor Table）中的代码段描述符。
// - `boot_pml4_addr`：引导加载程序的页目录表PML4（Page Map Level 4）的物理地址。
// - `zero_page_addr`：内存中的一个零页面（Zero Page）的物理地址，用于某些特殊的引导操作。
// - `segments`：一个名为`BootGdtSegment`的结构体，用于描述GDT和IDT（Interrupt Descriptor Table）的相关信息。
//
// 2. `BootGdtSegment`结构体：
// - `code_segment`和`data_segment`：这两个字段都是`kvm_segment`类型的结构体，用于描述GDT中的代码段和数据段的相关信息，包括段的起始地址、大小、访问权限等。
// - `gdt_base`：GDT（Global Descriptor Table）的起始物理地址。
// - `gdt_limit`：GDT的限制（大小）。
// - `idt_base`：IDT（Interrupt Descriptor Table）的起始物理地址。
// - `idt_limit`：IDT的限制（大小）。
//
// 这些结构体的定义中使用了一些特定的数据类型，如`u64`表示64位无符号整数，`u16`表示16位无符号整数，`kvm_segment`是一个与KVM（Kernel-based Virtual Machine）相关的结构体，用于描述段的信息。
//
// 这些结构体的具体值和用途可能取决于具体的应用场景和代码逻辑，在上下文中可能会进行填充或修改。这里给出的定义只是结构体的基本成员和功能说明。
//
/// The start address for some boot source in guest memory for `x86_64`.
#[derive(Debug, Default, Copy, Clone)]
pub struct X86BootLoader {
    pub boot_ip: u64,
    pub boot_sp: u64,
    pub boot_selector: u16,
    pub boot_pml4_addr: u64,
    pub zero_page_addr: u64,
    pub segments: BootGdtSegment,
}

#[derive(Debug, Default, Copy, Clone)]
pub struct BootGdtSegment {
    pub code_segment: kvm_segment,
    pub data_segment: kvm_segment,
    pub gdt_base: u64,
    pub gdt_limit: u16,
    pub idt_base: u64,
    pub idt_limit: u16,
}

pub fn load_linux(
    config: &X86BootLoaderConfig,
    sys_mem: &Arc<AddressSpace>,
    fwcfg: Option<&Arc<Mutex<dyn FwCfgOps>>>,
) -> Result<X86BootLoader> {
    if config.prot64_mode {
        direct_boot::load_linux(config, sys_mem)
    } else {
        // `fwcfg` 是指 Firmware Configuration（固件配置）的缩写，也称为 QEMU Firmware Configuration。它是 QEMU （Quick EMUlator）虚拟化软件中的一个组件，用于提供虚拟机中的固件配置。
        //
        // 在虚拟化环境中，虚拟机通常需要一些特定的配置信息，例如启动顺序、BIOS设置、设备参数等。这些配置信息通常由虚拟机的固件（如BIOS或UEFI）管理。
        //
        // fwcfg 提供了一种机制，使得主机和虚拟机之间能够通过一组键值对的方式传递配置信息。主机可以使用 QEMU 的命令行参数或 API 来设置 fwcfg 键值对，并将其传递给虚拟机。
        //
        // 虚拟机在启动时可以读取 fwcfg 键值对，并根据其中的配置信息进行相应的初始化或操作。虚拟机中的操作系统、引导加载器或其他组件可以使用 fwcfg 键值对来获取配置参数，以便进行自定义的初始化或配置。
        //
        // fwcfg 键值对的具体内容和用途可以根据需求进行定义和扩展。通常，fwcfg 键值对包含一些常用的配置参数，如内核命令行、设备启动顺序、时钟设置等。这些参数可以在虚拟机启动时传递给操作系统或引导加载器，以定制化虚拟机的行为。
        //
        // 总结来说，fwcfg 是 QEMU 虚拟化软件中的一种机制，用于传递虚拟机的固件配置信息。通过 fwcfg 键值对，主机可以向虚拟机传递特定的配置参数，以便虚拟机中的组件根据这些参数进行初始化或配置。

        let fwcfg = fwcfg.with_context(|| "Failed to load linux: No FwCfg provided")?;
        let mut locked_fwcfg = fwcfg.lock().unwrap();
        standard_boot::load_linux(config, sys_mem, &mut *locked_fwcfg)?;

        Ok(X86BootLoader {
            boot_ip: 0xFFF0,
            boot_sp: 0x8000,
            boot_selector: 0xF000,
            ..Default::default()
        })
    }
}
