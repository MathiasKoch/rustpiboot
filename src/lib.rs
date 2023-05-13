//! Boot raspberry pi devices into mass storage mode

use core::time::Duration;
use rusb::{
    request_type, Context, Device, DeviceHandle, Direction, Error, Recipient, RequestType,
    UsbContext,
};
use std::convert::TryInto;
use std::thread;

#[derive(Debug)]
pub enum RpiError {
    FailedOpenDevice,
    DeviceNotFound,
    WriteError,
    ReadError,
    UnknownMessage,
    IoError,
}

#[derive(Debug)]
pub enum Command {
    GetFileSize = 0,
    ReadFile = 1,
    Done = 2,
}

impl std::convert::TryFrom<u32> for Command {
    type Error = RpiError;

    fn try_from(orig: u32) -> Result<Self, Self::Error> {
        Ok(match orig {
            0 => Command::GetFileSize,
            1 => Command::ReadFile,
            2 => Command::Done,
            _ => return Err(RpiError::UnknownMessage),
        })
    }
}

const BOOTCODE_BIN: &[u8] = include_bytes!("msd/bootcode.bin");
const BOOTCODE4_BIN: &[u8] = include_bytes!("msd/bootcode4.bin");
const START_ELF: &[u8] = include_bytes!("msd/start.elf");
const START4_ELF: &[u8] = include_bytes!("msd/start4.elf");

const LIBUSB_MAX_TRANSFER: usize = 16 * 1024;

fn get_device<T: UsbContext>(
    usb_ctx: &T,
    pid: u16,
) -> Result<(Device<T>, DeviceHandle<T>, bool), RpiError> {
    let mut is_bcm2711 = false;

    if let Ok(devices) = usb_ctx.devices() {
        match devices.iter().enumerate().find(|(i, dev)| {
            if let Ok(desc) = dev.device_descriptor() {
                log::trace!(
                    "Found device {:?} idVendor=0x{:x?} idProduct=0x{:0x?}",
                    i + 1,
                    desc.vendor_id(),
                    desc.product_id()
                );
                log::trace!("Bus: {:?}, Device: {:?}", dev.bus_number(), dev.address());
                if desc.vendor_id() == pid {
                    let prod_id = desc.product_id();
                    if prod_id == 0x2763 || prod_id == 0x2764 || prod_id == 0x2711 {
                        log::trace!("Found candidate Compute Module... ");
                        log::trace!("Device located successfully");
                        is_bcm2711 = prod_id == 0x2711;
                        return true;
                    }
                }
            }
            false
        }) {
            Some((_, device)) => {
                thread::sleep(Duration::from_secs(1));
                match device.open() {
                    Ok(handle) => Ok((device, handle, is_bcm2711)),
                    Err(Error::Access) => {
                        log::debug!("Permission to access USB device denied. Make sure you are a member of the plugdev group.");
                        std::process::exit(1);
                    }
                    Err(e) => {
                        log::trace!("Failed to open the requested device - {:?}", e);
                        Err(RpiError::FailedOpenDevice)
                    }
                }
            }
            None => Err(RpiError::DeviceNotFound),
        }
    } else {
        Err(RpiError::DeviceNotFound)
    }
}

fn ep_write<T: UsbContext>(
    dev_handle: &DeviceHandle<T>,
    endpoint: u8,
    buf: &[u8],
) -> Result<usize, RpiError> {
    dev_handle
        .write_control(
            request_type(Direction::Out, RequestType::Vendor, Recipient::Device),
            0,
            (buf.len() & 0xffff).try_into().unwrap(),
            (buf.len() >> 16).try_into().unwrap(),
            &[],
            Duration::from_secs(1),
        )
        .unwrap();

    let mut sent = 0;
    for chunk in buf.chunks(LIBUSB_MAX_TRANSFER) {
        sent += dev_handle
            .write_bulk(endpoint, chunk, Duration::from_secs(1))
            .map_err(|_| RpiError::WriteError)?;
    }
    log::trace!("write_bulk sent: {:?} bytes", sent);
    Ok(sent)
}

fn ep_read<T: UsbContext>(dev_handle: &DeviceHandle<T>, buf: &mut [u8]) -> Result<usize, RpiError> {
    dev_handle
        .read_control(
            request_type(Direction::In, RequestType::Vendor, Recipient::Device),
            0,
            (buf.len() & 0xffff).try_into().unwrap(),
            (buf.len() >> 16).try_into().unwrap(),
            buf,
            Duration::from_secs(1),
        )
        .map_err(|e| match e {
            Error::NoDevice => RpiError::DeviceNotFound,
            Error::Io => RpiError::IoError,
            _ => RpiError::ReadError,
        })
}

fn second_stage_boot<T: UsbContext>(
    dev_handle: &DeviceHandle<T>,
    out_ep: u8,
    boot_message: &[u8],
) -> Result<u32, RpiError> {
    ep_write(dev_handle, out_ep, &boot_message[0..24])?;

    log::trace!("Writing {} bytes", boot_message.len());

    let size = ep_write(dev_handle, out_ep, boot_message)?;
    if size != boot_message.len() {
        log::debug!("Failed to write correct length, returned {}", size);
        return Err(RpiError::WriteError);
    };

    thread::sleep(Duration::from_secs(1));

    let buf = &mut [0; 4];
    let size = ep_read(dev_handle, buf)?;
    let retcode = u32::from_le_bytes(*buf);
    if size > 0 && retcode == 0 {
        log::debug!("Successful read {:?} bytes", size);
    } else {
        log::debug!("Failed : 0x{:x?}", retcode);
    }

    Ok(retcode)
}

fn file_server<T: UsbContext>(
    dev_handle: &DeviceHandle<T>,
    out_ep: u8,
    start_message: &[u8],
) -> Result<(), RpiError> {
    let message = &mut [0; 260];
    loop {
        if let Err(e) = ep_read(dev_handle, message) {
            // Drop out if the device goes away
            match e {
                RpiError::DeviceNotFound | RpiError::IoError => {
                    break;
                }
                _ => {
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
            }
        }
        let command: Command = u32::from_le_bytes(message[0..4].try_into().unwrap())
            .try_into()
            .map_err(|e| {
                log::debug!("{:?}", &message[0..4]);
                e
            })?;
        let nul_range_end = message[4..]
            .iter()
            .position(|&c| c == b'\0')
            .unwrap_or_else(|| message[4..].len()); // default to length if no `\0` present

        let fname = std::str::from_utf8(&message[4..nul_range_end + 4]).unwrap();
        log::trace!("Received message {:?}: {:?}", command, fname);

        if fname.is_empty() {
            ep_write(dev_handle, out_ep, &[])?;
            break;
        }

        match command {
            Command::GetFileSize => {
                // TODO: this is a dirty hack that works only because bootcode.bin and bootcode4.bin
                // (sent in second_stage_boot) request start.elf and start4.elf respectively.
                // Ideally, there should be a more robust filename lookup.
                if fname == "start.elf" || fname == "start4.elf" {
                    dev_handle
                        .write_control(
                            request_type(Direction::Out, RequestType::Vendor, Recipient::Device),
                            0,
                            (start_message.len() & 0xffff).try_into().unwrap(),
                            (start_message.len() >> 16).try_into().unwrap(),
                            &[],
                            Duration::from_secs(1),
                        )
                        .unwrap();
                } else {
                    ep_write(dev_handle, out_ep, &[])?;
                    log::trace!("Cannot open file {:?}", fname);
                }
            }
            Command::ReadFile => {
                log::debug!("File read: {:?}", fname);
                let size = ep_write(dev_handle, out_ep, start_message)?;
                if size != start_message.len() {
                    log::debug!("Failed to write complete file to USB device");
                    return Err(RpiError::WriteError);
                }
            }
            Command::Done => {
                break;
            }
        }
    }
    log::debug!("Second stage boot server done");
    Ok(())
}

pub struct Options {
    // directory: Option<String>,
    overlay: bool,
    delay: u64,
    // signed: bool,
    port: Option<u8>,
    loop_forever: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            // directory: None,
            overlay: false,
            delay: 500,
            // signed: false,
            port: None,
            loop_forever: false,
        }
    }
}

pub fn boot(options: Options) -> Result<(), RpiError> {
    // let signed_boot = if options.signed {
    //   Some(include_bytes!("bootsig.bin"))
    // } else {
    //   None
    // };

    let usb_ctx = Context::new().expect("Failed to create usb context");
    let mut found_device: Option<(DeviceHandle<Context>, Device<Context>, u8, u8)> = None;
    let mut second_stage = BOOTCODE_BIN;
    let mut start = START_ELF;

    loop {
        log::debug!("Waiting for BCM2835/6/7/2711...");

        // Wait for a device to get plugged in
        loop {
            match get_device(&usb_ctx, 0x0a5c) {
                Err(_) => {
                    thread::sleep(Duration::from_micros(200));
                    continue;
                }
                Ok((device, mut handle, is_bcm2711)) => {
                    let config = device
                        .active_config_descriptor()
                        .expect("Failed to read config descriptor");
                    let (interface, out_ep, in_ep) = if config.num_interfaces() == 1 {
                        (0, 1, 2)
                    } else {
                        (1, 3, 4)
                    };

                    if is_bcm2711 {
                        second_stage = BOOTCODE4_BIN;
                        start = START4_ELF;
                    }

                    if let Err(e) = handle.claim_interface(interface) {
                        drop(handle);
                        log::debug!("Failed to claim interface - {:?}", e);
                        thread::sleep(Duration::from_micros(options.delay));
                        continue;
                    }
                    log::trace!("Initialised device correctly");

                    let desc = device.device_descriptor().expect("No device descriptor!");

                    log::trace!(
                        "Found serial number {:?}",
                        desc.serial_number_string_index()
                    );

                    match found_device {
                        None => {
                            found_device = Some((handle, device, out_ep, in_ep));
                            break;
                        }
                        Some((_, ref fd, _, _)) => {
                            if desc.serial_number_string_index()
                                == fd.device_descriptor().unwrap().serial_number_string_index()
                            {
                                handle.release_interface(interface).unwrap();
                                drop(handle);
                                thread::sleep(Duration::from_micros(200));
                                continue;
                            } else {
                                found_device = Some((handle, device, out_ep, in_ep));
                                break;
                            }
                        }
                    }
                }
            }
        }

        if let Some((ref dev_handle, ref device, out_ep, _in_ep)) = found_device {
            let desc = device.device_descriptor().unwrap();
            if desc.serial_number_string_index() == None
                || desc.serial_number_string_index() == Some(3)
            {
                log::debug!("Sending bootcode.bin");
                second_stage_boot(dev_handle, out_ep, second_stage)?;
            } else {
                log::debug!("Second stage boot server");
                file_server(dev_handle, out_ep, start)?;
            }

            thread::sleep(Duration::from_secs(1));

            if desc.serial_number_string_index() != None && !options.loop_forever {
                break;
            }
        }
    }

    Ok(())
}
