#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

use core::fmt::Write;
use flatbuffers::{FlatBufferBuilder, Follow};
use graphics_server::api::GlyphStyle;
use graphics_server::{DrawStyle, Gid, PixelColor, Point, Rectangle, TextBounds, TextView};
use num_traits::*;
use pddb::Pddb;
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

#[derive(Debug, Clone)]
enum TotpAlgorithm {
    HmacSha1,
    HmacSha256,
    HmacSha512,
}

#[derive(Debug)]
struct TotpEntry {
    name: String,
    step_seconds: u16,
    secret_hash: Vec<u8>,
    digit_count: u8,
    algorithm: TotpAlgorithm,
}

#[derive(Debug)]
enum Error {
    Io(std::io::Error),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

fn get_current_unix_time() -> Result<u64, SystemTimeError> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
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
                name: "Fake Entry 1".to_string(),
                step_seconds: 30,
                secret_hash: vec![0xDE, 0xAD, 0xBE, 0xEF],
                digit_count: 6,
                algorithm: TotpAlgorithm::HmacSha256,
            },
            TotpEntry {
                name: "Fake Entry 2".to_string(),
                step_seconds: 30,
                secret_hash: vec![0xDE, 0xAD, 0xBE, 0xEF],
                digit_count: 6,
                algorithm: TotpAlgorithm::HmacSha256,
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
            write!(text_view.text, "{}: {}", entry.name, current_ts)
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
