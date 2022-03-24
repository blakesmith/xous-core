#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

use core::fmt::Write;
use flatbuffers::FlatBufferBuilder;
use graphics_server::api::GlyphStyle;
use graphics_server::{DrawStyle, Gid, PixelColor, Point, Rectangle, TextBounds, TextView};
use num_traits::*;
use pddb::Pddb;
use std::io::Write as PddbWrite;
use xtotp_generated::xtotp::{TotpEntry, TotpEntryArgs};

mod xtotp_generated;

pub(crate) const SERVER_NAME_XTOTP: &str = "_Xtotp Authenticator_";

const XTOTP_ENTRIES_DICT: &'static str = "xtotp.otp_entries";

/// Top level application events.
#[derive(Debug, num_derive::FromPrimitive, num_derive::ToPrimitive)]
pub(crate) enum HelloOp {
    /// Redraw the screen
    Redraw = 0,

    /// Quit the application
    Quit,
}

struct Hello {
    content: Gid,
    gam: gam::Gam,
    _gam_token: [u32; 4],
    screensize: Point,
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

impl Hello {
    fn new(xns: &xous_names::XousNames, sid: xous::SID) -> Self {
        let gam = gam::Gam::new(&xns).expect("Can't connect to GAM");
        let gam_token = gam
            .register_ux(gam::UxRegistration {
                app_name: xous_ipc::String::<128>::from_str(gam::APP_NAME_XTOTP),
                ux_type: gam::UxType::Chat,
                predictor: None,
                listener: sid.to_array(),
                redraw_id: HelloOp::Redraw.to_u32().unwrap(),
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
        write!(text_view.text, "{}", "Hello Xtotp!").expect("Could not write to text view");

        self.gam
            .post_textview(&mut text_view)
            .expect("Could not render text view");
        self.gam.redraw().expect("Could not redraw screen");
    }
}

fn persist_static_totp_entry(pddb: &mut Pddb) -> Result<(), Error> {
    let mut fb_builder = FlatBufferBuilder::new();

    let static_secret: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];

    let args = TotpEntryArgs {
        name: Some(fb_builder.create_string("Fake Entry")),
        step_seconds: 30,
        secret_hash: Some(fb_builder.create_vector(static_secret)),
        digit_count: 6,
    };

    let _entry_offset = TotpEntry::create(&mut fb_builder, &args);
    let serialized = fb_builder.finished_data();

    let mut entry = pddb.get(
        XTOTP_ENTRIES_DICT,
        "static_fake_entry",
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
    persist_static_totp_entry(&mut pddb).expect("Could not persist static / test TOTP entry");

    let mut hello = Hello::new(&xns, sid);

    loop {
        let msg = xous::receive_message(sid).unwrap();
        log::debug!("Got message: {:?}", msg);

        match FromPrimitive::from_usize(msg.body.id()) {
            Some(HelloOp::Redraw) => {
                log::debug!("Got redraw");
                hello.redraw();
            }
            Some(HelloOp::Quit) => {
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
