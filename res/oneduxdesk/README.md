# OneDux Desk customization

OneDux Desk is a customized build of [RustDesk](https://github.com/rustdesk/rustdesk) (AGPL-3.0).
Upstream copyright notices are kept; this fork's source is published here as the AGPL requires.

- `custom.json` — the settings baked into OneDux Desk builds (app name, defaults, locked settings).
- `custom.txt` — `custom.json` signed with OneDux's Ed25519 key; shipped next to the executable and
  read by `load_custom_client()` in `src/common.rs`. The matching public key is the `KEY` constant in
  `read_custom_client()`. The private key is not in this repository.

Locked settings (`override-settings`): WebRTC, the upstream update check and auto-update are off, so the
client does not contact third-party STUN servers or `api.rustdesk.com`. With no server configured the
client stays offline instead of falling back to the public rustdesk.com servers.
