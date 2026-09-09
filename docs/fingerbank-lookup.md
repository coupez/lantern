# Fingerbank DHCP lookup

`lantern fingerbank` is an explicit, offline-first review and optional remote
lookup of DHCP packet observations that were previously written by Lantern. It
does not capture traffic, start a DHCP exchange, scan the network, or join a
packet to a current scanner device.

Fingerbank's v2 combinations endpoint accepts DHCP patterns and returns a best
matching device with a score and hierarchy. Its documentation also says that a
query for an unknown combination can add that combination to the provider
database. [Fingerbank v2 interrogate API](https://api.fingerbank.org/api_doc/2/combinations/interrogate.html),
[Fingerbank usage guide](https://www.fingerbank.org/usage/). Treat submission
as disclosure of the selected DHCP-derived request to that external service.

## Review first

Create one bounded aggregate observation file. `--jsonl` is a streaming format
and is not the input to this command.

```sh
./bin/lantern observe --read capture.pcap --json --limit 5000 > observe.json
./bin/lantern fingerbank --read observe.json
```

The default command is local-only preview. It accepts an observation file up to
17 MiB and can display up to 5,000 packets,
whether each is an eligible client request, the exact provider payload that
would be sent, its SHA-256 digest, and limited source provenance: input-file
digest, packet number, capture time, PCAP section/interface and link type.
It sends no network request and does not require an API key.

Eligible IPv4 packets have UDP direction 68 to 67, DHCP type Discover or
Request, and a nonempty option 55 request list. The capture schema does not
retain BOOTP op, so these checks do not authenticate client origin; relayed
IPv4 requests are excluded. IPv6 accepts Solicit, Request, Renew, Rebind and
Information-request with one nonempty option 6 request list, either directly
(546 to 547) or through only Relay-forward layers (547 to 547). Captured
truncation, ambiguous request lists and malformed vendor fields are rejected.
IPv4 vendor fragments concatenate in wire order; IPv6 submits only the
enterprise number from one well-framed vendor-class option. Relay options and
derived display hints do not contribute payload attributes.

Review one packet before allowing any remote request:

```sh
./bin/lantern fingerbank --read observe.json --packet 42
```

Eligibility is determined from the preserved DHCP message and observed packet
direction. Server replies, relayed material that cannot form a client request,
and ambiguous or incomplete messages remain local preview rows rather than
being submitted. A provider payload uses the retained DHCP option order; it
does not sort, merge, or infer a different client fingerprint. Packet number is
the review handle. Lantern does not merge packets into clients by IP address,
MAC address, client ID, hostname, lease address, transaction ID, or name.

## Submit exactly one reviewed packet

Remote lookup is deliberately one packet and one request per invocation in the
initial implementation. `--submit` requires a selected `--packet` and an API
key environment-variable name:

```sh
export FINGERBANK_API_KEY='your-account-key'
./bin/lantern fingerbank --read observe.json --packet 42 \
  --submit --key-env FINGERBANK_API_KEY
```

The key is never accepted on the command line and is not written into preview
or result JSON. Fingerbank documents an API key for interrogate requests and
also permits an Authorization header. Lantern uses the fixed HTTPS provider
endpoint, a request budget of one, no retries, and no redirect fallback.
[Fingerbank API v2 authentication](https://api.fingerbank.org/api_doc/2/combinations/interrogate.html).
The provider's [header documentation](https://api.fingerbank.org/api_doc/2/static.html)
specifies the Bearer scheme. The client has a 10-second total request deadline,
32 KiB response-header limit and 128 KiB response-body limit. It uses no proxy
from the environment. HTTP 404 produces an unknown classification; other
unsuccessful statuses produce a failed report and nonzero exit without retries.

The resulting record keeps the selected packet's limited provenance, exact
request payload digest, and provider response. It records provider score and
device hierarchy as provider classification data. It is not an authenticated
device identity, a measured hardware model, a retail-model catalog result, or a
network reachability observation.

## Interpretation limits

DHCP option patterns overlap across operating systems, device families,
versions, privacy profiles, and vendor implementations. A high provider score
is still a provider database match for a supplied pattern, not proof that the
captured endpoint is that physical product. The response can include a broad
ancestor category as well as a leaf device; retain that hierarchy rather than
silently promoting it to a model claim.

Fingerbank classifications remain separate from Lantern scanner identities,
inventory observations, and the `reported_model`, `retail_model`, `family`,
and `kind` evaluation namespaces. There is no automatic IP/client merge and no
automatic evaluation credit. Any later comparison with independently labeled
truth requires an explicit packet-to-case mapping and a separately named
provider evaluation input.

Lantern does not ship a full Fingerbank catalog replica and it does not claim
parity with Fing or any other commercial scanner. No real-account or
physical-device interoperability result is included with this feature. The
local preview is therefore useful even without an account: it makes the exact
packet-derived payload and its disclosure boundary reviewable before a remote
lookup.

The offline capture decoder and its source-provenance limits are documented in
[DHCP observations](dhcp-observations.md). Raw DHCP option bytes and the
capture file may contain sensitive identifiers; keep both files under the same
access controls you would apply to network telemetry.
