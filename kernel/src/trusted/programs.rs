//! The ring-3 programs assembled into the kernel image for the boot
//! verification of the native services (the volume service and the packet
//! producers and consumers in `kernel/*.S`), read as `'static` byte slices.
//!
//! Each program lies between a start and an end symbol in the kernel's
//! text, which is mapped for the whole boot and never written, so a slice
//! of it is valid for `'static`. [`Program::bytes`] is the only place the
//! symbols become a slice; the address-space code copies the bytes into a
//! domain's code page.

use core::arch::global_asm;

const PAGE_SIZE: usize = 4096;

global_asm!(include_str!("../../volume-service.S"));
global_asm!(include_str!("../../packet-consumer.S"));
global_asm!(include_str!("../../packet-wait.S"));
global_asm!(include_str!("../../packet-backpressure.S"));
global_asm!(include_str!("../../packet-protocol-loop.S"));
global_asm!(include_str!("../../packet-ipv4.S"));
global_asm!(include_str!("../../packet-egress-consumer.S"));
global_asm!(include_str!("../../packet-egress-wait.S"));
global_asm!(include_str!("../../packet-egress-backpressure.S"));
global_asm!(include_str!("../../packet-egress-ack-backpressure.S"));
global_asm!(include_str!("../../packet-egress-reuse.S"));
global_asm!(include_str!("../../packet-egress-batch.S"));

// Only the symbols' addresses are taken; nothing calls them from the kernel.
extern "C" {
    fn linox_volume_writer_start();
    fn linox_volume_writer_fault();
    fn linox_volume_writer_end();
    fn linox_volume_reader_start();
    fn linox_volume_reader_end();
    fn linox_packet_consumer_start();
    fn linox_packet_consumer_end();
    fn linox_packet_wait_producer_start();
    fn linox_packet_wait_producer_end();
    fn linox_packet_wait_consumer_start();
    fn linox_packet_wait_consumer_end();
    fn linox_packet_wait_stop_helper_start();
    fn linox_packet_wait_stop_helper_end();
    fn linox_packet_wait_timeout_consumer_start();
    fn linox_packet_wait_timeout_consumer_end();
    fn linox_packet_wait_timeout_helper_start();
    fn linox_packet_wait_timeout_helper_end();
    fn linox_packet_egress_wait_producer_start();
    fn linox_packet_egress_wait_producer_end();
    fn linox_packet_egress_backpressure_producer_start();
    fn linox_packet_egress_backpressure_producer_end();
    fn linox_packet_egress_backpressure_consumer_start();
    fn linox_packet_egress_backpressure_consumer_end();
    fn linox_packet_egress_ack_backpressure_producer_start();
    fn linox_packet_egress_ack_backpressure_producer_end();
    fn linox_packet_egress_reuse_producer_start();
    fn linox_packet_egress_reuse_producer_end();
    fn linox_packet_egress_batch_producer_start();
    fn linox_packet_egress_batch_producer_end();
    fn linox_packet_backpressure_producer_start();
    fn linox_packet_backpressure_producer_end();
    fn linox_packet_backpressure_consumer_start();
    fn linox_packet_backpressure_consumer_end();
    fn linox_packet_protocol_loop_producer_start();
    fn linox_packet_protocol_loop_producer_end();
    fn linox_packet_ipv4_producer_start();
    fn linox_packet_ipv4_producer_end();
    fn linox_packet_egress_consumer_start();
    fn linox_packet_egress_consumer_end();
}

/// One of the assembled ring-3 programs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Program {
    VolumeWriter,
    VolumeReader,
    PacketConsumer,
    PacketWaitProducer,
    PacketWaitConsumer,
    PacketWaitStopHelper,
    PacketWaitTimeoutConsumer,
    PacketWaitTimeoutHelper,
    PacketEgressWaitProducer,
    PacketEgressBackpressureProducer,
    PacketEgressBackpressureConsumer,
    PacketEgressAckBackpressureProducer,
    PacketEgressReuseProducer,
    PacketEgressBatchProducer,
    PacketBackpressureProducer,
    PacketBackpressureConsumer,
    PacketProtocolLoopProducer,
    PacketIpv4Producer,
    PacketEgressConsumer,
}

impl Program {
    /// The program's start and end symbols.
    fn bounds(self) -> (usize, usize) {
        // A symbol's address, without calling it.
        macro_rules! bounds {
            ($start:ident, $end:ident) => {
                ($start as *const () as usize, $end as *const () as usize)
            };
        }
        match self {
            Self::VolumeWriter => bounds!(linox_volume_writer_start, linox_volume_writer_end),
            Self::VolumeReader => bounds!(linox_volume_reader_start, linox_volume_reader_end),
            Self::PacketConsumer => bounds!(linox_packet_consumer_start, linox_packet_consumer_end),
            Self::PacketWaitProducer => bounds!(
                linox_packet_wait_producer_start,
                linox_packet_wait_producer_end
            ),
            Self::PacketWaitConsumer => bounds!(
                linox_packet_wait_consumer_start,
                linox_packet_wait_consumer_end
            ),
            Self::PacketWaitStopHelper => bounds!(
                linox_packet_wait_stop_helper_start,
                linox_packet_wait_stop_helper_end
            ),
            Self::PacketWaitTimeoutConsumer => bounds!(
                linox_packet_wait_timeout_consumer_start,
                linox_packet_wait_timeout_consumer_end
            ),
            Self::PacketWaitTimeoutHelper => bounds!(
                linox_packet_wait_timeout_helper_start,
                linox_packet_wait_timeout_helper_end
            ),
            Self::PacketEgressWaitProducer => bounds!(
                linox_packet_egress_wait_producer_start,
                linox_packet_egress_wait_producer_end
            ),
            Self::PacketEgressBackpressureProducer => bounds!(
                linox_packet_egress_backpressure_producer_start,
                linox_packet_egress_backpressure_producer_end
            ),
            Self::PacketEgressBackpressureConsumer => bounds!(
                linox_packet_egress_backpressure_consumer_start,
                linox_packet_egress_backpressure_consumer_end
            ),
            Self::PacketEgressAckBackpressureProducer => bounds!(
                linox_packet_egress_ack_backpressure_producer_start,
                linox_packet_egress_ack_backpressure_producer_end
            ),
            Self::PacketEgressReuseProducer => bounds!(
                linox_packet_egress_reuse_producer_start,
                linox_packet_egress_reuse_producer_end
            ),
            Self::PacketEgressBatchProducer => bounds!(
                linox_packet_egress_batch_producer_start,
                linox_packet_egress_batch_producer_end
            ),
            Self::PacketBackpressureProducer => bounds!(
                linox_packet_backpressure_producer_start,
                linox_packet_backpressure_producer_end
            ),
            Self::PacketBackpressureConsumer => bounds!(
                linox_packet_backpressure_consumer_start,
                linox_packet_backpressure_consumer_end
            ),
            Self::PacketProtocolLoopProducer => bounds!(
                linox_packet_protocol_loop_producer_start,
                linox_packet_protocol_loop_producer_end
            ),
            Self::PacketIpv4Producer => bounds!(
                linox_packet_ipv4_producer_start,
                linox_packet_ipv4_producer_end
            ),
            Self::PacketEgressConsumer => bounds!(
                linox_packet_egress_consumer_start,
                linox_packet_egress_consumer_end
            ),
        }
    }

    /// The program's code: at most a page, which is all a test domain's
    /// code page holds.
    pub(crate) fn bytes(self) -> Option<&'static [u8]> {
        let (start, end) = self.bounds();
        let size = end.checked_sub(start)?;
        if size == 0 || size > PAGE_SIZE {
            return None;
        }
        // SAFETY: `start` and `end` are the start and end symbols of one
        // program in the kernel's text (the `.S` files above), which stays
        // mapped for the whole boot and is never written.
        Some(unsafe { core::slice::from_raw_parts(start as *const u8, size) })
    }
}

/// The offset in the volume writer of the instruction that faults on
/// purpose.
pub(crate) fn volume_writer_fault_offset() -> usize {
    linox_volume_writer_fault as *const () as usize
        - linox_volume_writer_start as *const () as usize
}
