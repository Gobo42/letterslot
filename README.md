# letterslot

Single static Go binary, no dependencies. Two listeners:

| Port | Who | Paths |
|---|---|---|
| `:8080` | public, via the share.example.com proxy | `GET /dl/<token>`, `GET/POST /upload/` — everything else is 404, no index |
| `:80` | you, LAN only | admin page: files, links, download counts, incoming uploads |

- Tokens are 8 base62 chars from `crypto/rand` (~48 bits; old 16-char links keep working). An IP that requests 2 unknown tokens is blocked from the public side (list + Unblock in the admin page). Downloads are sent as `Content-Disposition: attachment` with the real filename, and range/resume works.
- Links never expire by default; pick 1/7/30/90 days per link in the admin page. Expired, revoked and unknown tokens all return a plain 404.
- Public uploads stream straight to disk (RAM use stays flat), are stored under generated names in `incoming/` and are never served publicly. Limits: size cap (`-max-upload`), per-IP rate limit (`-upload-rate`/hour), and a disk-space floor (`-min-free`).
- State (links, upload metadata) is a single JSON file: `/var/lib/letterslot/state.json`. Back that file up.

## Install (minimal Debian trixie)

As root. Replace `youruser` with your login on that box.

```sh
# copy letterslot-linux-amd64 and letterslot.service over first (scp)

useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin letterslot
usermod -aG letterslot youruser                      # lets you read/delete uploads over ssh

install -d -m 0755 /srv/share
install -d -o youruser     -g letterslot -m 2775 /srv/share/files      # you scp here; letterslot can move uploads in
install -d -o letterslot -g letterslot -m 2770 /srv/share/incoming   # public uploads

install -m 0755 letterslot-linux-amd64 /usr/local/bin/letterslot
install -m 0644 letterslot.service /etc/systemd/system/letterslot.service
systemctl daemon-reload
systemctl enable --now letterslot
systemctl status letterslot
journalctl -u letterslot -f                       # downloads/uploads are logged here
```

Log out and back in after the `usermod` so the group applies.

## Daily use

```sh
scp bigfile.iso user@yourserver:/srv/share/files/          # subdirectories are fine too
```

Then open `http://<box-ip>/`, click **New link** next to the file, and copy the URL. Each file can have several links (e.g. one per person, with a note), and each can be revoked on its own.

Uploads appear under **Incoming uploads**. Download them, delete them, or use **Move to files** to put one into `files/` so you can link it.

Hidden files (`.foo`, rsync temp files) aren't listed. Symlinks inside `files/` that point outside it are refused, so copy files in rather than symlinking.

## Proxy side

See `nginx.conf.snippet`. Remove any old `location /upload` block that points at port 80, because that port is the admin page.

Test from outside:

```sh
curl -F file=@test.txt https://share.example.com/upload/
curl -OJ https://share.example.com/dl/<token>
```

## Flags

| Flag | Default |
|---|---|
| `-public` | `0.0.0.0:8080` |
| `-admin` | `0.0.0.0:80` |
| `-files` | `/srv/share/files` |
| `-incoming` | `/srv/share/incoming` (must be on the same filesystem as `-files` for **Move to files**) |
| `-state` | `/var/lib/letterslot/state.json` |
| `-base-url` | `https://share.example.com` (only used to display links) |
| `-max-upload` | `2G` per request (match nginx `client_max_body_size`) |
| `-min-free` | `4G` (uploads are refused below this) |
| `-upload-rate` | `20` requests per IP per hour (`0` = unlimited) |
| `-allow-file` | none. File of IPs/CIDRs, one per line (`#` comments ok), that are never blocked or upload-rate-limited. Read at startup, so restart after editing |

## Building from source

```sh
apt install golang-go          # trixie ships Go 1.24, which is what this needs
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o letterslot .
```

## License

MIT, see [LICENSE](LICENSE).
