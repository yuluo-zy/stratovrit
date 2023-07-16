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

use std::sync::Arc;

use address_space::AddressSpace;
use util::byte_code::ByteCode;

use super::{
    X86BootLoaderConfig, EBDA_START, MB_BIOS_BEGIN, REAL_MODE_IVT_BEGIN, VGA_RAM_BEGIN,
    VMLINUX_RAM_START,
};
use crate::error::BootLoaderError;
use anyhow::{anyhow, Result};

pub const E820_RAM: u32 = 1;
pub const E820_RESERVED: u32 = 2;
pub const BOOT_VERSION: u16 = 0x0200;
pub const BOOT_FLAG: u16 = 0xAA55;
pub const HDRS: u32 = 0x5372_6448;
pub const UNDEFINED_ID: u8 = 0xFF;
// Loader type ID: OVMF UEFI virtualization stack.
pub const UEFI_OVMF_ID: u8 = 0xB;

// Structures below sourced from:
// https://www.kernel.org/doc/html/latest/x86/boot.html
// https://www.kernel.org/doc/html/latest/x86/zero-page.html
/// 实模式内核头部信息
/// RealModeKernelHeader（实模式内核头部）是x86引导过程中用于描述内核的头部信息的数据结构。它包含了一系列字段，用于指定内核的各种属性和参数。以下是RealModeKernelHeader的详细字段说明：
//
// 1. `setup_sects`：占用的扇区数目，用于指定内核加载器在内存中的占用空间大小。
// 2. `root_flags`：根文件系统的标志。
// 3. `syssize`：实模式下系统的大小，以字节为单位。
// 4. `ram_size`：实模式下可用的RAM大小，以KB为单位。
// 5. `video_mode`：显示模式。
// 6. `root_dev`：根文件系统设备的设备号。
// 7. `boot_flag`：引导标志，通常为0xAA55。
// 8. `jump`：引导加载器执行的跳转指令。
// 9. `header`：内核头部标志，通常为0x5372_6448。
// 10. `version`：内核版本。
// 11. `realmode_swtch`：实模式切换的地址。
// 12. `start_sys_seg`：系统开始的段。
// 13. `kernel_version`：内核版本号。
// 14. `type_of_loader`：加载器的类型。
// 15. `loadflags`：加载标志。
// 16. `setup_move_size`：加载器的移动大小。
// 17. `code32_start`：32位代码的起始地址。
// 18. `ramdisk_image`：ramdisk（内存盘）的内存地址。
// 19. `ramdisk_size`：ramdisk的大小。
// 20. `bootsect_kludge`：引导扇区修复。
// 21. `heap_end_ptr`：堆结束指针。
// 22. `ext_loader_ver`：扩展加载器版本。
// 23. `ext_loader_type`：扩展加载器类型。
// 24. `cmdline_ptr`：命令行参数的内存地址。
// 25. `initrd_addr_max`：初始化rd的最大地址。
// 26. `kernel_alignment`：内核对齐方式。
// 27. `relocatable_kernel`：内核是否可重定位。
// 28. `min_alignment`：最小对齐方式。
// 29. `xloadflags`：加载标志。
// 30. `cmdline_size`：命令行参数的大小。
// 31. `hardware_subarch`：硬件子架构。
// 32. `hardware_subarch_data`：硬件子架构数据。
// 33. `payload_offset`：有效载荷偏移量。
// 34. `payload_length`：有效载荷长度。
// 35. `setup_data`：设置数据。
// 36. `pref_address`：首选地址。
// 37. `init_size`：初始化大小。
// 38. `handover_offset`：移交偏移量。
// 39. `kernel_info_offset`：内核信息偏移量。
// RealModeKernelHeader中的这些字段提供了内核启动过程中所需的关键信息，包括内存布局、加载器信息、命令行参数等。这些信息对于正确加载和执行内核非常重要。
#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct RealModeKernelHeader {
    pub setup_sects: u8,
    root_flags: u16,
    syssize: u32,
    ram_size: u16,
    video_mode: u16,
    root_dev: u16,
    boot_flag: u16,
    jump: u16,
    pub header: u32,
    pub version: u16,
    realmode_swtch: u32,
    start_sys_seg: u16,
    kernel_version: u16,
    pub type_of_loader: u8,
    pub loadflags: u8,
    setup_move_size: u16,
    pub code32_start: u32,
    ramdisk_image: u32,
    ramdisk_size: u32,
    bootsect_kludge: u32,
    heap_end_ptr: u16,
    ext_loader_ver: u8,
    ext_loader_type: u8,
    cmdline_ptr: u32,
    initrd_addr_max: u32,
    kernel_alignment: u32,
    relocatable_kernel: u8,
    min_alignment: u8,
    xloadflags: u16,
    cmdline_size: u32,
    hardware_subarch: u32,
    hardware_subarch_data: u64,
    payload_offset: u32,
    payload_length: u32,
    setup_data: u64,
    pref_address: u64,
    init_size: u32,
    handover_offset: u32,
    kernel_info_offset: u32,
}

// 实模式（Real Mode）是x86架构中的一种操作模式，它是处理器在引导过程中的初始模式。在实模式下，处理器处于最基本的运行状态，具有较少的保护和功能。
//
// 以下是实模式的一些特点和限制：
//
// 1. 16位寻址：在实模式下，处理器使用16位地址总线进行内存寻址，最大支持寻址到1MB的物理内存空间。
//
// 2. 段式内存管理：实模式使用段寄存器和段描述符来管理内存。内存被分为不同的段，每个段的大小可以是64KB。段寄存器存储段选择子，用于指定当前操作所使用的内存段。
//
// 3. 段重叠和访问控制：实模式下，不同的段可以重叠，这可能导致内存访问冲突。此外，实模式没有提供内存保护和访问控制机制，任何程序都可以访问系统内存。
//
// 4. 16位寄存器和指令：在实模式下，通用寄存器和指令都是16位的，限制了数据和指令的处理能力。
//
// 5. 仅有一个特权级：实模式没有提供多个特权级别，所有代码都在同一特权级下执行。
//
// 实模式主要用于系统引导过程中，当计算机启动时，处理器处于实模式下，执行BIOS固件代码，加载操作系统内核。随着操作系统的加载和切换到保护模式，实模式被逐渐弃用，因为它的功能和保护机制受到限制。保护模式提供了更强大的内存管理和访问控制，支持32位和64位寻址，以及多个特权级别，使操作系统能够更好地管理系统资源和提供更高级的功能。
// 除了实模式（Real Mode），x86架构还包括以下模式：
//
// 1. 保护模式（Protected Mode）：保护模式是x86架构中较高级的操作模式之一。在保护模式下，处理器提供了更强大的内存管理、访问控制和特权级别机制。它支持32位寻址和分段机制，可以访问更大的内存空间（超过1MB），并且可以实现虚拟内存、分页机制和多任务处理。
//
// 2. 长模式（Long Mode）：长模式是x86架构中的64位模式，也称为x86-64或AMD64。在长模式下，处理器支持64位寻址和指令集，可以访问更大的内存空间（高达18.4 million TB）和更丰富的寄存器集。它扩展了保护模式的功能，并引入了新的64位指令。
//
// 3. 系统管理模式（System Management Mode，SMM）：SMM是一种特殊的操作模式，用于系统管理和控制。在SMM下，处理器运行在最低特权级别，可以处理系统管理中断，例如电源管理、温度监控和安全功能。
//
// 4. 虚拟8086模式（Virtual 8086 Mode）：虚拟8086模式允许在保护模式下运行实模式的软件，以实现对旧软件的兼容性支持。在虚拟8086模式下，处理器模拟了一个实模式的环境，使得实模式的软件可以在保护模式下运行，同时可以利用保护模式的特性。
//
// 这些模式在x86架构中提供了不同的功能和特性，可以满足不同场景下的需求。保护模式和长模式是现代操作系统的主要模式，用于实现强大的内存管理、多任务处理和扩展指令集等功能。实模式主要用于系统引导阶段和一些特殊用途的操作系统或应用程序。而SMM和虚拟8086模式则提供了额外的特性，用于特定的系统管理和兼容性需求。
impl ByteCode for RealModeKernelHeader {}

impl RealModeKernelHeader {
    pub fn new() -> Self {
        RealModeKernelHeader {
            boot_flag: BOOT_FLAG,
            header: HDRS,
            type_of_loader: UNDEFINED_ID,
            ..Default::default()
        }
    }

    pub fn check_valid_kernel(&self) -> Result<()> {
        if self.header != HDRS { // 在实模式内核头部的数据结构中，header 字段被用来存储这个标志值，以便在加载内核时进行验证和识别。通过检查 header 字段是否等于 HDRS，可以确保内核头部的正确性和有效性。
            return Err(anyhow!(BootLoaderError::ElfKernel));
        }
        if (self.version < BOOT_VERSION) || ((self.loadflags & 0x1) == 0x0) {
            return Err(anyhow!(BootLoaderError::InvalidBzImage));
        }
        if self.version < 0x202 {
            return Err(anyhow!(BootLoaderError::OldVersionKernel));
        }
        Ok(())
    }

    pub fn set_cmdline(&mut self, cmdline_addr: u32, cmdline_size: u32) {
        self.cmdline_ptr = cmdline_addr;
        self.cmdline_size = cmdline_size;
    }

    pub fn set_ramdisk(&mut self, addr: u32, size: u32) {
        self.ramdisk_image = addr;
        self.ramdisk_size = size;
    }
}

// E820内存映射表（E820 Memory Map）是一种由BIOS或UEFI固件提供的数据结构，用于描述系统中可用的内存区域。它提供了有关内存地址范围、大小和类型（如RAM、保留、ACPI等）的信息。
//
// 在x86架构的计算机系统中，E820内存映射表通常在引导过程中由固件填充，并由操作系统内核在启动时读取和解析。操作系统可以根据这个表来了解系统中哪些内存区域是可用的，以便进行内存管理和分配。
//
// E820内存映射表的条目（Entry）描述了不同的内存区域。每个条目包含以下信息：
//
// 1. 起始地址（Start Address）：内存区域的起始物理地址。
// 2. 大小（Size）：内存区域的大小，以字节为单位。
// 3. 类型（Type）：内存区域的类型，例如RAM、保留区域、ACPI等。
//
// 通过解析E820内存映射表，操作系统可以确定可用的内存范围，并进行内存分配、页表设置、设备映射等操作。这对于操作系统的正常运行和管理系统资源非常重要。
#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct E820Entry {
    addr: u64,
    size: u64,
    type_: u32,
}

impl E820Entry {
    pub(crate) fn new(addr: u64, size: u64, type_: u32) -> E820Entry {
        E820Entry { addr, size, type_ }
    }
}

impl ByteCode for E820Entry {}


// BootParams 结构体是引导参数的主要结构。它包含了引导过程中所需的各种信息，如屏幕信息、APM BIOS信息、硬盘信息、E820内存映射表等。
// 其中，kernel_header 字段是一个 RealModeKernelHeader 结构体，用于描述内核的头部信息。
// 如何使用 BootParams 结构来设置 E820 内存映射表的条目


// `BootParams` 结构体是引导参数的主要数据结构，用于在引导过程中传递各种信息给操作系统内核。下面是 `BootParams` 结构体的详细字段含义：
//
// 1. `screen_info`：屏幕信息，用于保存引导加载器显示相关的信息。
//
// 2. `apm_bios_info`：APM BIOS（高级电源管理）信息，包含与系统电源管理相关的数据。
//
// 3. `pad1`：填充字段，保持结构体对齐。
//
// 4. `tboot_addr`：Tboot地址，保留字段，用于可信启动相关。
//
// 5. `ist_info`：IST（Interrupt Stack Table）信息，保存中断堆栈表相关的数据。
//
// 6. `pad2`：填充字段，保持结构体对齐。
//
// 7. `hd0_info`：第一个硬盘信息，包含硬盘的参数和几何信息。
//
// 8. `hd1_info`：第二个硬盘信息，与 `hd0_info` 类似。
//
// 9. `sys_desc_table`：系统描述符表，保存系统描述符表相关的数据。
//
// 10. `olpc_ofw_header`：OLPC OFW（One Laptop Per Child Open Firmware）头部信息，特定于 OLPC 项目。
//
// 11. `ext_ramdisk_image`：扩展的RAMDisk（内存盘）映像地址。
//
// 12. `ext_ramdisk_size`：扩展的RAMDisk大小。
//
// 13. `ext_cmd_line_ptr`：扩展命令行参数的内存地址。
//
// 14. `pad3`：填充字段，保持结构体对齐。
//
// 15. `edid_info`：EDID（Extended Display Identification Data）信息，保存显示器的详细信息。
//
// 16. `efi_info`：EFI（Extensible Firmware Interface）信息，保存与EFI固件相关的数据。
//
// 17. `alt_mem_k`：备用内存大小，以KB为单位。
//
// 18. `scratch`：用于临时存储数据的字段。
//
// 19. `e820_entries`：E820内存映射表的条目数。
//
// 20. `eddbuf_entries`：EDD（Enhanced Disk Drive）缓冲区条目数。
//
// 21. `edd_mbr_sig_buf_entries`：EDD MBR（Master Boot Record）签名缓冲区条目数。
//
// 22. `kbd_status`：键盘状态。
//
// 23. `secure_boot`：安全启动标志。
//
// 24. `pad4`：填充字段，保持结构体对齐。
//
// 25. `sentinel`：标志字段，用于识别结构体的完整性。
//
// 26. `pad5`：填充字段，保持结构体对齐。
//
// 27. `kernel_header`：实模式内核头部信息，包含描述内核的详细字段。
//
// 28. `pad6`：填充字段，保持结构体对齐。
//
// 29. `edd_mbr_sig_buffer`：EDD MBR签名缓冲区，用于存储磁盘的MBR签名。
//
// 30. `e820_table`：E820内存映射表的数组，保存了系统中各个内存区域的起始地址、大小和类型。
//
// 31. `pad8`：填充字段，保持结构体对齐。
//
// 32. `edd_buf`：EDD缓冲区，用于存储磁盘的相关信息。
//
// 这些字段用于在引导过程中传递各种信息给操作系统内核，包括显示信息、硬盘信息、内存映射表、命令行参数等。操作系统内核可以根据这些信息进行初始化和配置，以正确地加载和运行系统。
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct BootParams {
    screen_info: [u8; 0x40],
    apm_bios_info: [u8; 0x14],
    pad1: u32,
    tboot_addr: [u8; 0x8],
    ist_info: [u8; 0x10],
    pad2: [u8; 0x10],
    hd0_info: [u8; 0x10],
    hd1_info: [u8; 0x10],
    sys_desc_table: [u8; 0x10],
    olpc_ofw_header: [u8; 0x10],
    ext_ramdisk_image: u32,
    ext_ramdisk_size: u32,
    ext_cmd_line_ptr: u32,
    pad3: [u8; 0x74],
    edid_info: [u8; 0x80],
    efi_info: [u8; 0x20],
    alt_mem_k: u32,
    scratch: u32,
    e820_entries: u8,
    eddbuf_entries: u8,
    edd_mbr_sig_buf_entries: u8,
    kbd_status: u8,
    secure_boot: u8,
    pad4: u16,
    sentinel: u8,
    pad5: u8,
    kernel_header: RealModeKernelHeader, // offset: 0x1f1
    pad6: [u8; 0x24],
    edd_mbr_sig_buffer: [u8; 0x40],
    e820_table: [E820Entry; 0x80],
    pad8: [u8; 0x30],
    eddbuf: [u8; 0x1ec],
}

impl ByteCode for BootParams {}

impl Default for BootParams {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}

impl BootParams {
    pub fn new(kernel_header: RealModeKernelHeader) -> Self {
        BootParams {
            kernel_header,
            ..Default::default()
        }
    }

    pub fn add_e820_entry(&mut self, addr: u64, size: u64, type_: u32) {
        self.e820_table[self.e820_entries as usize] = E820Entry::new(addr, size, type_);
        self.e820_entries += 1;
    }

    pub fn setup_e820_entries(
        &mut self,
        config: &X86BootLoaderConfig,
        sys_mem: &Arc<AddressSpace>,
    ) {
        // e820 条目类型
        // Usable：已经被映射到物理内存的物理地址。
        // Reserved：这些区间是没有被映射到任何地方，不能当作RAM来使用，但是kernel可以决定将这些区间映射到其他地方，比如PCI设备。通过检查/proc/iomem这个虚拟文件，就可以知道这些reserved的空间，是如何进一步分配给不同的设备来使用了。
        // ACPI data：映射到用来存放ACPI数据的RAM空间，操作系统应该将ACPI Table读入到这个区间内。
        // ACPI NVS：映射到用来存放ACPI数据的非易失性存储空间，操作系统不能使用。
        // Unusable：表示检测到发生错误的物理内存。这个在上面例子里没有，因为比较少见。
        //
        // IVT（Interrupt Vector Table，中断向量表）是在 x86 架构中用于管理和处理中断的重要数据结构之一。它是一个存储中断处理程序入口地址的表，每个中断都有一个对应的向量（0-255），也称为中断号或中断向量。
        //
        // IVT 的位置固定在实模式内存的起始地址（0x0000:0x0000），占据 1KB 的空间。每个中断向量占用 4 字节，包含了中断处理程序的实模式入口地址（段地址和偏移地址）。
        //
        // 当发生中断时，处理器会根据中断号从 IVT 中获取对应的中断处理程序的入口地址，并跳转到该地址执行相应的中断处理程序。每个中断处理程序负责处理特定类型的中断，如时钟中断、键盘中断、硬盘中断等。
        //
        // 在实模式下，IVT 是一个固定的表，无法被修改。操作系统或引导加载器可以通过设置 IVT 来注册和安装自定义的中断处理程序，从而实现对特定中断的自定义处理。

        self.add_e820_entry(
            REAL_MODE_IVT_BEGIN,
            EBDA_START - REAL_MODE_IVT_BEGIN,
            E820_RAM,
        ); // 为 IVT（Interrupt Vector Table）设置了一个 E820 内存映射条目，类型为 RAM。


        // 为 EBDA（Extended BIOS Data Area）设置了一个 E820 内存映射条目，类型为保留。
        // EBDA（Extended BIOS Data Area，扩展BIOS数据区）是在x86架构中的实模式下，BIOS所提供的一块内存区域。它位于实模式内存地址的高端，通常在640KB（0xA0000）和1MB（0x100000）之间。
        //
        // EBDA的大小可变，由BIOS决定，并且BIOS在系统启动时会检测系统的可用内存并分配一部分作为EBDA。它提供了额外的内存空间，用于存储BIOS和系统启动期间的一些重要数据和设置。EBDA的用途包括但不限于以下方面：
        //
        // 1. 系统配置信息：EBDA存储了一些重要的系统配置信息，如硬件设备的信息、中断向量表和其他与系统设置相关的数据。
        //
        // 2. BIOS扩展功能：EBDA中存储了一些BIOS扩展功能的数据结构和参数，以支持特定的硬件功能或高级功能。
        //
        // 3. ACPI（Advanced Configuration and Power Interface）数据：ACPI是一种电源管理标准，EBDA可以用于存储与ACPI相关的数据结构和配置信息。
        //
        // 4. 临时存储区域：在系统引导过程中，EBDA可以用作临时存储区域，存储一些暂时性的数据或临时变量。
        //
        // EBDA的具体大小和位置可以通过读取BIOS数据区域（BIOS Data Area）的相关字段获取。在实模式下，软件可以通过访问EBDA来获取和修改其中存储的数据，以满足特定的系统需求和配置。然而，随着计算机体系结构的发展，随着进入保护模式和64位模式，EBDA的重要性和使用情况逐渐减少，由更高级的机制和数据结构取而代之。
        self.add_e820_entry(EBDA_START, VGA_RAM_BEGIN - EBDA_START, E820_RESERVED);
        // 为 MB_BIOS_BEGIN 设置了一个 E820 内存映射条目，类型为保留。
        self.add_e820_entry(MB_BIOS_BEGIN, 0, E820_RESERVED);

        let high_memory_start = VMLINUX_RAM_START;
        let layout_32bit_gap_end = config.gap_range.0 + config.gap_range.1;
        let mem_end = sys_mem.memory_end_address().raw_value();
        //  layout_32bit_gap_end 是一个变量，用于表示实模式下的 32 位布局间隙的结束地址。
        //
        // 在实模式中，32 位布局间隙（32-bit Addressing Gap）是为了兼容性而引入的一段保留地址空间。它位于实模式内存的高端，从地址 0x100000（1MB）开始，结束于 0xA0000（640KB）。这个间隙是为了在从实模式切换到保护模式时提供一段未使用的地址空间，以避免与旧的实模式软件发生冲突。
        //
        // layout_32bit_gap_end 变量用于表示这个 32 位布局间隙的结束地址。在 setup_e820_entries 函数中，根据 config.gap_range 的设置，计算并将结果赋值给 layout_32bit_gap_end。
        //
        // 具体而言，如果 config.gap_range 的起始地址为 0xC0000000，结束地址为 0x40000000，则 layout_32bit_gap_end 的值将为 0xC0000000 + 0x40000000 = 0x100000000（64-bit地址空间中的 4GB）。
        //
        // 这个值将用于设置 e820_table 中的相应内存映射表条目，以标识实模式下 32 位布局间隙的起始和结束地址，并将其类型设置为 RAM 类型。这样，操作系统内核在加载和管理内存时可以正确识别和处理这段地址空间。
        if mem_end < layout_32bit_gap_end {
            self.add_e820_entry(high_memory_start, mem_end - high_memory_start, E820_RAM);
        } else {
            self.add_e820_entry(
                high_memory_start,
                config.gap_range.0 - high_memory_start,
                E820_RAM,
            );
            self.add_e820_entry(
                layout_32bit_gap_end,
                mem_end - layout_32bit_gap_end,
                E820_RAM,
            );
        }
    }
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;
    use std::sync::Arc;

    use address_space::{AddressSpace, GuestAddress, HostMemMapping, Region};

    use super::super::X86BootLoaderConfig;
    use super::*;

    #[test]
    fn test_boot_param() {
        let root = Region::init_container_region(0x2000_0000, "root");
        let space = AddressSpace::new(root.clone(), "space").unwrap();
        let ram1 = Arc::new(
            HostMemMapping::new(
                GuestAddress(0),
                None,
                0x1000_0000,
                None,
                false,
                false,
                false,
            )
            .unwrap(),
        );
        let region_a = Region::init_ram_region(ram1.clone(), "region_a");
        root.add_subregion(region_a, ram1.start_address().raw_value())
            .unwrap();

        let config = X86BootLoaderConfig {
            kernel: Some(PathBuf::new()),
            initrd: Some(PathBuf::new()),
            kernel_cmdline: String::from("this_is_a_piece_of_test_string"),
            cpu_count: 2,
            gap_range: (0xC000_0000, 0x4000_0000),
            ioapic_addr: 0xFEC0_0000,
            lapic_addr: 0xFEE0_0000,
            prot64_mode: false,
            ident_tss_range: None,
        };

        let boot_hdr = RealModeKernelHeader::default();
        let mut boot_params = BootParams::new(boot_hdr);
        boot_params.setup_e820_entries(&config, &space);
        assert_eq!(boot_params.e820_entries, 4);

        assert!(boot_params.e820_table[0].addr == 0);

        assert!(boot_params.e820_table[0].addr == 0);
        assert!(boot_params.e820_table[0].size == 0x0009_FC00);
        assert!(boot_params.e820_table[0].type_ == 1);

        assert!(boot_params.e820_table[1].addr == 0x0009_FC00);
        assert!(boot_params.e820_table[1].size == 0x400);
        assert!(boot_params.e820_table[1].type_ == 2);

        assert!(boot_params.e820_table[2].addr == 0x000F_0000);
        assert!(boot_params.e820_table[2].size == 0);
        assert!(boot_params.e820_table[2].type_ == 2);

        assert!(boot_params.e820_table[3].addr == 0x0010_0000);
        assert!(boot_params.e820_table[3].size == 0x0ff0_0000);
        assert!(boot_params.e820_table[3].type_ == 1);
    }
}
