#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

use core::fmt::Write;
use flatbuffers::{FlatBufferBuilder, Follow};
use graphics_server::api::GlyphStyle;
use graphics_server::{DrawStyle, Gid, PixelColor, Point, Rectangle, TextBounds, TextView};
use num_traits::*;
use pddb::Pddb;
use std::io::{Read, Write as PddbWrite};
use xtotp_generated::xtotp::{TotpAlgorithm, TotpEntry, TotpEntryArgs};

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
    read_buf: Vec<u8>,
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
        Self {
            gam,
            _gam_token: gam_token,
            content,
            screensize,
            db,
            read_buf: Vec::new(),
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
        self.read_buf.clear();
        self.clear_area();

        let entry = lookup_totp_entry(&mut self.db, "Fake Entry", &mut self.read_buf)
            .expect("Could not lookup Totp entry");

        let mut text_view = TextView::new(
            self.content,
            TextBounds::GrowableFromBr(
                Point::new(
                    self.screensize.x - (self.screensize.x / 2),
                    self.screensize.y - (self.screensize.y / 2),
                ),
                (self.screensize.x / 5 * 4) as u16,
            ),
        );

        text_view.border_width = 1;
        text_view.draw_border = true;
        text_view.clear_area = true;
        text_view.rounded_border = Some(3);
        text_view.style = GlyphStyle::Regular;
        write!(text_view.text, "{}", entry.name().unwrap_or("Entry"))
            .expect("Could not write to text view");

        self.gam
            .post_textview(&mut text_view)
            .expect("Could not render text view");
        self.gam.redraw().expect("Could not redraw screen");
    }
}

fn persist_totp_entry(
    db: &mut Pddb,
    fbb: &mut FlatBufferBuilder,
    name: &str,
    step_seconds: u16,
    secret: &[u8],
    digit_count: u8,
    algorithm: TotpAlgorithm,
) -> Result<(), Error> {
    let args = TotpEntryArgs {
        name: Some(fbb.create_string(name)),
        step_seconds: step_seconds,
        secret_hash: Some(fbb.create_vector(secret)),
        digit_count: digit_count,
        algorithm: algorithm,
    };

    let _entry_offset = TotpEntry::create(fbb, &args);
    let serialized = fbb.finished_data();

    let mut entry = db.get(
        XTOTP_ENTRIES_DICT,
        name,
        None,
        true,
        true,
        None,
        Some(|| {}),
    )?;
    entry.write(serialized)?;
    entry.flush()?;
    Ok(())
}

fn lookup_totp_entry<'buf>(
    db: &mut Pddb,
    name: &str,
    buf: &'buf mut Vec<u8>,
) -> Result<TotpEntry<'buf>, Error> {
    let mut entry = db.get(
        XTOTP_ENTRIES_DICT,
        name,
        None,
        false,
        false,
        None,
        Some(|| {}),
    )?;

    entry.read_to_end(buf)?;
    Ok(TotpEntry::follow(buf, 0))
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

    let mut fbb = FlatBufferBuilder::new();
    persist_totp_entry(
        &mut pddb,
        &mut fbb,
        "Fake Entry",
        30,
        &[0xDE, 0xAD, 0xDE, 0xEF],
        6,
        TotpAlgorithm::HmacSha256,
    )
    .expect("Could not persist static / test TOTP entry");

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
