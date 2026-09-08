package ui

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Buffer fragmented UTF-8/CSI input. Pasted content is ignored so a pasted q,
// Ctrl-C, or escape sequence cannot act as a command.
type keyDecoder struct {
	pending string
	paste   bool
}

func (d *keyDecoder) flushEscape() []string {
	if d.pending == "\x1b" && !d.paste {
		d.pending = ""
		return []string{"escape"}
	}
	return nil
}
func (d *keyDecoder) feed(s string) (out []string) {
	d.pending += s
	for len(d.pending) > 0 {
		if d.paste {
			if i := strings.Index(d.pending, "\x1b[201~"); i >= 0 {
				d.pending = d.pending[i+6:]
				d.paste = false
				continue
			}
			// Keep only a possible partial closing delimiter.
			if len(d.pending) > 5 {
				d.pending = d.pending[len(d.pending)-5:]
			}
			break
		}
		if d.pending[0] == 0x1b {
			if len(d.pending) < 2 {
				break
			}
			if d.pending[1] == '[' || d.pending[1] == 'O' {
				end := 2
				for end < len(d.pending) && !(d.pending[end] >= 0x40 && d.pending[end] <= 0x7e) {
					end++
				}
				if end == len(d.pending) {
					if end > 64 {
						d.pending = ""
					}
					break
				}
				seq := d.pending[:end+1]
				d.pending = d.pending[end+1:]
				if seq == "\x1b[200~" {
					d.paste = true
					continue
				}
				var key string
				switch seq {
				case "\x1b[A", "\x1bOA":
					key = "up"
				case "\x1b[B", "\x1bOB":
					key = "down"
				case "\x1b[5~":
					key = "pageup"
				case "\x1b[6~":
					key = "pagedown"
				// Normal/application cursor keys and screen/Linux/rxvt variants.
				case "\x1b[H", "\x1bOH", "\x1b[1~", "\x1b[7~":
					key = "home"
				case "\x1b[F", "\x1bOF", "\x1b[4~", "\x1b[8~":
					key = "end"
				case "\x1bOM":
					key = "enter"
				}
				if key != "" {
					out = append(out, key)
				}
				continue
			}
			// Consume unknown Alt keys instead of interpreting their payload as commands.
			if !utf8.FullRuneInString(d.pending[1:]) {
				break
			}
			_, n := utf8.DecodeRuneInString(d.pending[1:])
			d.pending = d.pending[n+1:]
			continue
		}
		if !utf8.FullRuneInString(d.pending) {
			break
		}
		r, n := utf8.DecodeRuneInString(d.pending)
		d.pending = d.pending[n:]
		switch r {
		case 3:
			out = append(out, "quit")
		case 13, 10:
			out = append(out, "enter")
		case 127, 8:
			out = append(out, "backspace")
		default:
			if !unicode.IsControl(r) && r != utf8.RuneError {
				out = append(out, string(r))
			}
		}
	}
	return out
}
