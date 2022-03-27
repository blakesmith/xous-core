#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

use core::fmt::Write;
use crypto_common::InvalidLength;
use flatbuffers::{FlatBufferBuilder, Follow};
use graphics_server::api::GlyphStyle;
use graphics_server::{DrawStyle, Gid, PixelColor, Point, Rectangle, TextBounds, TextView};
use hmac::{Hmac, Mac};
use num_traits::*;
use pddb::Pddb;
use sha1::Sha1;
use std::{
    io::{Read, Write as PddbWrite},
    time::{SystemTime, SystemTimeError},
};

mod xtotp_generated;

pub(crate) const SERVER_NAME_XTOTP: &str = "_Xtotp Authenticator_";

const XTOTP_ENTRIES_DICT: &'static str = "xtotp.otp_entries";

/// Top level application events.
#[derive(Debug, num_derive::FromPrimitive, num_derive::ToPrimitive)]
pub(crate) enum XtotpOp {
    /// Redraw the screen
    Redraw = 0,

    /// Quit the application
    Quit,
}

struct Xtotp {
    content: Gid,
    gam: gam::Gam,
    db: Pddb,
    _gam_token: [u32; 4],
    screensize: Point,

    totp_entries: Vec<TotpEntry>,
}

#[derive(Debug, Clone, Copy)]
enum TotpAlgorithm {
    HmacSha1,
    HmacSha256,
    HmacSha512,
}

#[derive(Debug)]
struct TotpEntry {
    name: String,
    step_seconds: u16,
    shared_secret: Vec<u8>,
    digit_count: u8,
    algorithm: TotpAlgorithm,
}

#[derive(Debug)]
enum Error {
    Io(std::io::Error),
    DigestLength(InvalidLength),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<InvalidLength> for Error {
    fn from(err: InvalidLength) -> Self {
        Error::DigestLength(err)
    }
}

fn get_current_unix_time() -> Result<u64, SystemTimeError> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
}

fn unpack_u64(v: u64) -> [u8; 8] {
    let mask = 0x00000000000000ff;
    let mut bytes: [u8; 8] = [0; 8];
    (0..8).for_each(|i| bytes[7 - i] = (mask & (v >> (i * 8))) as u8);
    bytes
}

fn generate_hmac_bytes(unix_timestamp: u64, totp_entry: &TotpEntry) -> Result<Vec<u8>, Error> {
    let mut computed_hmac = Vec::new();
    match totp_entry.algorithm {
        // The OpenTitan HMAC core does not support hmac-sha1. Fall back to
        // a software implementation.
        TotpAlgorithm::HmacSha1 => {
            let mut mac: Hmac<Sha1> = Hmac::new_from_slice(&totp_entry.shared_secret)?;
            mac.update(&unpack_u64(unix_timestamp / totp_entry.step_seconds as u64));
            let hash: &[u8] = &mac.finalize().into_bytes();
            computed_hmac.extend_from_slice(hash);
        }
        algorithm => todo!(),
    }

    Ok(computed_hmac)
}

fn generate_totp_code(unix_timestamp: u64, totp_entry: &TotpEntry) -> Result<String, Error> {
    let hash = generate_hmac_bytes(unix_timestamp, totp_entry)?;
    let offset: usize = (hash.last().unwrap_or(&0) & 0xf) as usize;
    let binary: u64 = (((hash[offset] & 0x7f) as u64) << 24)
        | ((hash[offset + 1] as u64) << 16)
        | ((hash[offset + 2] as u64) << 8)
        | (hash[offset + 3] as u64);

    let truncated_code = format!(
        "{:01$}",
        binary % (10_u64.pow(totp_entry.digit_count as u32)),
        totp_entry.digit_count as usize
    );

    Ok(truncated_code)
}

impl Xtotp {
    fn new(xns: &xous_names::XousNames, sid: xous::SID, db: Pddb) -> Self {
        let gam = gam::Gam::new(&xns).expect("Can't connect to GAM");
        let gam_token = gam
            .register_ux(gam::UxRegistration {
                app_name: xous_ipc::String::<128>::from_str(gam::APP_NAME_XTOTP),
                ux_type: gam::UxType::Chat,
                predictor: None,
                listener: sid.to_array(),
                redraw_id: XtotpOp::Redraw.to_u32().unwrap(),
                gotinput_id: None,
                audioframe_id: None,
                rawkeys_id: None,
                focuschange_id: None,
            })
            .expect("Could not register GAM UX")
            .unwrap();

        let content = gam
            .request_content_canvas(gam_token)
            .expect("Could not get content canvas");
        let screensize = gam
            .get_canvas_bounds(content)
            .expect("Could not get canvas dimensions");

        let totp_entries = vec![
            TotpEntry {
                name: "GitHub".to_string(),
                step_seconds: 30,
                shared_secret: vec![0xDE, 0xAD, 0xBE, 0xEF],
                digit_count: 6,
                algorithm: TotpAlgorithm::HmacSha1,
            },
            TotpEntry {
                name: "Google".to_string(),
                step_seconds: 30,
                shared_secret: vec![0xDE, 0xAD, 0xBE, 0xED],
                digit_count: 6,
                algorithm: TotpAlgorithm::HmacSha1,
            },
        ];
        Self {
            gam,
            _gam_token: gam_token,
            content,
            screensize,
            db,
            totp_entries,
        }
    }

    /// Clear the entire screen.
    fn clear_area(&self) {
        self.gam
            .draw_rectangle(
                self.content,
                Rectangle::new_with_style(
                    Point::new(0, 0),
                    self.screensize,
                    DrawStyle {
                        fill_color: Some(PixelColor::Light),
                        stroke_color: None,
                        stroke_width: 0,
                    },
                ),
            )
            .expect("can't clear content area");
    }

    /// Redraw the text view onto the screen.
    fn redraw(&mut self) {
        self.clear_area();

        let current_ts = get_current_unix_time().unwrap_or(0);

        for (i, entry) in self.totp_entries.iter().enumerate() {
            let totp_code = generate_totp_code(current_ts, entry).expect("Could not get totp code");
            let mut text_view = TextView::new(
                self.content,
                TextBounds::GrowableFromTl(
                    Point::new(0, (i * 20) as i16),
                    (self.screensize.x / 5 * 4) as u16,
                ),
            );

            text_view.border_width = 1;
            text_view.draw_border = true;
            text_view.clear_area = true;
            text_view.rounded_border = Some(3);
            text_view.style = GlyphStyle::Regular;
            write!(text_view.text, "{}: {}", entry.name, totp_code)
                .expect("Could not write to text view");

            self.gam
                .post_textview(&mut text_view)
                .expect("Could not render text view");
        }

        self.gam.redraw().expect("Could not redraw screen");
    }
}

#[xous::xous_main]
fn xmain() -> ! {
    log_server::init_wait().unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("Xtotp PID is {}", xous::process::id());

    let xns = xous_names::XousNames::new().unwrap();

    // Register the server with xous
    let sid = xns
        .register_name(SERVER_NAME_XTOTP, None)
        .expect("can't register server");

    let mut pddb = Pddb::new();
    pddb.is_mounted_blocking(None);

    let mut xtotp = Xtotp::new(&xns, sid, pddb);

    loop {
        let msg = xous::receive_message(sid).unwrap();
        log::debug!("Got message: {:?}", msg);

        match FromPrimitive::from_usize(msg.body.id()) {
            Some(XtotpOp::Redraw) => {
                log::debug!("Got redraw");
                xtotp.redraw();
            }
            Some(XtotpOp::Quit) => {
                log::info!("Quitting application");
                break;
            }
            _ => {
                log::error!("Got unknown message");
            }
        }
    }

    log::info!("Quitting");
    xous::terminate_process(0)
}
