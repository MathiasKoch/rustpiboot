//! Boot raspberry pi devices into mass storage mode

use core::time::Duration;
use libusb::{request_type, Context, Device, Direction, Recipient, RequestType, DeviceHandle};
use std::thread;
use std::convert::TryInto;

#[allow(dead_code)]
#[derive(Debug)]
pub struct RpiError {
    kind: Kind,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum Kind {
    FailedOpenDevice,
    DeviceNotFound,
    WriteError,
}

const LIBUSB_MAX_TRANSFER: usize = 16 * 1024;

fn get_device(usb_ctx: &Context, pid: u16) -> Result<Device, RpiError> {
    if let Ok(devices) = usb_ctx.devices() {
        match devices.iter().find(|dev| {
            if let Ok(desc) = dev.device_descriptor() {
                if desc.vendor_id() == pid {
                    let prod_id = desc.product_id();
                    if prod_id == 0x2763 || prod_id == 0x2764 || prod_id == 0x2711 {
                        return true;
                    }
                }
            }
            false
        }) {
            Some(device) => {
                thread::sleep(Duration::from_secs(1));
                match device.open() {
                    Ok(_) => Ok(device),
                    Err(_e) => {
                        println!("Failed to open the requested device");
                        Err(RpiError {
                            kind: Kind::FailedOpenDevice,
                        })
                    }
                }
            }
            None => Err(RpiError {
                kind: Kind::DeviceNotFound,
            }),
        }
    } else {
        Err(RpiError {
            kind: Kind::DeviceNotFound,
        })
    }
}

fn ep_write(dev_handle: &DeviceHandle, endpoint: u8, buf: &[u8]) -> Result<usize, RpiError> {
    dev_handle
        .write_control(
            request_type(Direction::In, RequestType::Vendor, Recipient::Device),
            0,
            buf.len().try_into().unwrap(),
            (buf.len() >> 16).try_into().unwrap(),
            buf,
            Duration::from_secs(1),
        )
        .expect("Failed control transfer!");

    let mut sent = 0;

    for chunk in buf.chunks(LIBUSB_MAX_TRANSFER) {
        sent += dev_handle
            .write_bulk(endpoint, chunk, Duration::from_secs(5))
            .map_err(|_| RpiError {
                kind: Kind::WriteError,
            })?;
    }

    Ok(sent)
}

fn second_stage_boot(
    dev_handle: &DeviceHandle,
    options: &Options,
    out_ep: u8,
    boot_message: &[u8],
) -> Result<(), RpiError> {
    let size = ep_write(dev_handle, out_ep, boot_message)?;
    if size != boot_message.len() {
        println!("Failed to write correct length, returned {}", size);
        return Err(RpiError {
            kind: Kind::WriteError,
        });
    };

    if options.verbose {
        println!("Writing {} bytes", boot_message.len());
    }

    Ok(())
}

fn file_server(dev_handle: &DeviceHandle) {}

pub struct Options {
    verbose: bool,
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
            verbose: false,
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
    println!("Attempting to boot device");
    let second_stage = include_bytes!("bootcode.bin");

    // let signed_boot = if options.signed {
    //   Some(include_bytes!("bootsig.bin"))
    // } else {
    //   None
    // };

    let usb_ctx = Context::new().expect("Failed to create usb context");
    let mut found_device: Option<(DeviceHandle, Device, u8, u8)> = None;

    loop {
        println!("Waiting for BCM2835/6/7/2711...");

        // Wait for a device to get plugged in
        loop {
            match get_device(&usb_ctx, 0x0a5c) {
                Err(_) => {
                    thread::sleep(Duration::from_micros(200));
                    continue;
                }
                Ok(device) => {
                    let config = device.active_config_descriptor().unwrap();
                    let (interface, out_ep, in_ep) = if config.num_interfaces() == 1 {
                        (0, 1, 2)
                    } else {
                        (1, 3, 4)
                    };

                    let mut handle = device.open().unwrap();

                    if handle.claim_interface(interface).is_err() {
                        println!("Failed to claim interface");
                        thread::sleep(Duration::from_micros(options.delay));
                        continue;
                    }

                    let desc = device.device_descriptor().unwrap();
                    match found_device {
                        None => drop(device),
                        Some((_, ref fd, _, _)) => {
                            if options.verbose {
                                println!(
                                    "Found serial number {:?}",
                                    desc.serial_number_string_index()
                                );
                            }

                            if desc.serial_number_string_index()
                                == fd.device_descriptor().unwrap().serial_number_string_index()
                            {
                                drop(device);
                            } else {
                                found_device = Some((handle, device, out_ep, in_ep));
                                break;
                            }
                        }
                    }
                }
            }
        }

        if let Some((ref dev_handle, ref device, out_ep, in_ep)) = found_device {
            let desc = device.device_descriptor().unwrap();
            if desc.serial_number_string_index() == Some(0)
                || desc.serial_number_string_index() == Some(3)
            {
                println!("Sending bootcode.bin");
                second_stage_boot(dev_handle, &options, out_ep, second_stage)?;
            } else {
                println!("Second stage boot server");
                file_server(dev_handle);
            }
            thread::sleep(Duration::from_secs(1));

            if desc.serial_number_string_index() != Some(0) && !options.loop_forever {
                break;
            }
        }
    }

    Ok(())
}
