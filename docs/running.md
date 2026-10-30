# Running onionglass

Status: pre-alpha. Personal mode works. Team and public modes are not built yet.

## Personal mode

Personal mode is for one person on their own machine. The gateway listens on `127.0.0.1` only and needs no sign-in, so it refuses to listen anywhere else.

### What you need

- Python 3.11 or newer.
- Tor running on your machine with its SOCKS port open. The default is port 9050.

Tor's own packages are the best source: the Tor Project's repository for Linux, `brew install tor` on macOS, and the Tor Expert Bundle on Windows. Use version 0.4.8 or newer, which some onion sites need to accept your connection.

### Start it

```bash
pip install .
onionglass
```

Then open `http://localhost:8080/` in your browser, type an onion address, and press Open.

Useful options:

| Option | Meaning |
|---|---|
| `--port 9000` | Listen on another port. |
| `--tor-port 9150` | Use another Tor SOCKS port. Repeat the option to spread visitors over several Tor processes. |
| `--tor-host 127.0.0.1` | Where Tor listens. |
| `--allow-images` | Load images from onion sites. Off by default, and when it is off no image is ever requested. |

### Using Tor Browser's Tor

If Tor Browser is running, its Tor listens on port 9150. `onionglass --tor-port 9150` works with it. Tor Browser does not turn on Tor's detailed failure reasons, so error pages will be less specific.

### Your browser and `*.localhost`

Each site you open is shown from its own host name under `localhost`, such as `abcd...wxyz.localhost`. Current Chrome, Edge and Firefox send those names to your own machine without any setup. If your browser does not, use a browser that does.

## Containers

```bash
docker compose up --build
```

Then open `http://localhost:8080/`. The compose file starts three containers:

- **tor**: Tor from the Tor Project's own package repository.
- **gateway**: onionglass, on a private network with no route to the internet.
- **proxy**: a small web proxy, the only thing published, and only on your machine's loopback address.

The container files have not been run by the project's maintainers yet. The continuous-integration job builds both images and checks the compose file, but nobody has watched them start Tor and open a site. Treat them as a starting point and read them first.

## What the gateway does and does not do for you

- Pages are shown without scripts.
- Images are not loaded unless you allow them.
- Links to the normal internet go through a warning page.
- The person running the gateway can see every address you open and everything you view. In personal mode that person is you.
- It does not make you anonymous. Use Tor Browser for that.

## Troubleshooting

| What you see | Likely cause |
|---|---|
| "Tor is not available" | Tor is not running, or the port is wrong. Check `--tor-port`. |
| "Site not found" | The onion site is offline or the address is wrong. |
| "Could not reach the site" | The site is busy. Try again in a minute. |
| "The page could not be shown safely" | The page was too large or complex to make safe. |
| Nothing opens after pressing Open | Your browser may not resolve `*.localhost`. Try another browser. |
