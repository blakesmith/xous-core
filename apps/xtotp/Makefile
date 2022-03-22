all: src/xtotp_generated.rs

src/xtotp_generated.rs:
	flatc -o src/ -r fbs/xtotp.fbs

clean:
	rm -rf src/xtotp_generated.rs

.PHONY: all clean
