# lightning [![Go](https://github.com/chfanghr/lightning/actions/workflows/go.yml/badge.svg)](https://github.com/chfanghr/lightning/actions/workflows/go.yml)

This is a ***WIP*** project.

The purpose of this project is to forward messages between a `qq` group and a `telegram` group.

## Getting Started

1. Clone this project: `git clone https://github.com/chfanghr/lightning.git`
2. Get dependencies by running [get_dependecies.sh](get_dependecies.sh) in the root of the repository
3. Fill the configuration file, save it as `config.json`.
    - Please refer to [`config.json.example`](config.json.example).
    - Redis configuration can be ignored if you use `docker-compose` to deploy this project.
4. Run `docker-compose build`
5. Run `docker-compose up -d`
6. Run `docker-compose logs -f` if you use qr code to log in to qq
7. Enjoy!

## Features

- [x] Forward text messages
- [x] Forward images
- [x] Recall messages from both `telegram` and `qq`
- [x] Forward telegram static stickers(including `gif`s)
- [x] Forward telegram tgs/animated stickers

## Troubleshooting

* The program always fails to send (text) messages to qq:
    - remove `session.token` and `device.json` in the `userdata` folder
    - restart services using `docker-compose restart`
    - log in to `qq` (if needed) again

## License

Licensed under the [MIT](LICENSE) license.
