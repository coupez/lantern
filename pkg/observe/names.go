package observe

import "fmt"

// MessageName is a protocol label, not a device-family or OS fingerprint.
func MessageName(version int, typ uint8) string {
	if version == 4 {
		names := map[uint8]string{1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
		if s := names[typ]; s != "" {
			return s
		}
	} else if version == 6 {
		names := map[uint8]string{1: "Solicit", 2: "Advertise", 3: "Request", 4: "Confirm", 5: "Renew", 6: "Rebind", 7: "Reply", 8: "Release", 9: "Decline", 10: "Reconfigure", 11: "Information-request", 12: "Relay-forward", 13: "Relay-reply"}
		if s := names[typ]; s != "" {
			return s
		}
	}
	return fmt.Sprintf("Type %d", typ)
}
